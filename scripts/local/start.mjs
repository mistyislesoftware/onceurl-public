import { spawn } from "node:child_process";
import { randomBytes } from "node:crypto";
import { mkdir, rm, writeFile } from "node:fs/promises";
import { dirname, join, relative, resolve, sep } from "node:path";
import { runDeliverySmoke } from "../delivery/smoke.mjs";
import { localCloudflareEnvironment, runPnpm } from "../database/helpers.mjs";
import {
  assertCondition,
  developmentEnvironment,
  localStateDirectory,
  resolveDevelopmentRuntime,
  rootDirectory,
  validateDevelopmentOriginPair
} from "./config.mjs";

const wranglerPath = join(rootDirectory, "node_modules", "wrangler", "bin", "wrangler.js");
const logDirectory = join(rootDirectory, ".tmp", "wrangler-logs");
const startupTimeoutMilliseconds = 45_000;

function repositoryOwnedStateDirectory(value) {
  const directory = resolve(value);
  const relativePath = relative(rootDirectory, directory);
  assertCondition(
    relativePath !== ".." && !relativePath.startsWith(`..${sep}`),
    "Wrangler persistence must remain inside the repository"
  );
  assertCondition(
    directory === localStateDirectory || relativePath.startsWith(`.tmp${sep}local-`),
    "Wrangler persistence must use .wrangler/state or an isolated .tmp/local-* test path"
  );
  return directory;
}

function prefixedOutput(label, buffer, target, recentOutput, quiet) {
  const text = buffer.toString();
  recentOutput.push(text);
  while (recentOutput.join("").length > 20_000) {
    recentOutput.shift();
  }

  if (quiet) {
    return;
  }

  for (const line of text.split(/\r?\n/u)) {
    if (line !== "") {
      target.write(`[${label}] ${line}\n`);
    }
  }
}

function workerArguments(service, runtime, stateDirectory, environmentFile) {
  const serviceContract = developmentEnvironment.local[service];
  const config =
    service === "functional"
      ? join(rootDirectory, "apps", "worker", "wrangler.jsonc")
      : join(rootDirectory, "apps", "marketing", "wrangler.jsonc");
  const listenIp = runtime.listenIp ?? serviceContract.hostname;

  const argumentsList = [
    wranglerPath,
    "dev",
    "--config",
    config,
    "--local",
    "--ip",
    listenIp,
    "--port",
    String(serviceContract.port),
    "--inspector-port",
    String(serviceContract.inspectorPort),
    "--local-protocol",
    runtime.listenProtocol,
    "--persist-to",
    stateDirectory,
    "--show-interactive-dev-session=false",
    "--var",
    "DEPLOYMENT_ENVIRONMENT:local",
    "--var",
    `MARKETING_ORIGIN:${runtime.marketingOrigin}`,
    "--var",
    `FUNCTIONAL_ORIGIN:${runtime.functionalOrigin}`
  ];
  if (service === "functional" && environmentFile !== null) {
    argumentsList.push("--env-file", environmentFile);
  }
  return argumentsList;
}

function startWorker(service, runtime, stateDirectory, quiet, environmentFile) {
  const recentOutput = [];
  const child = spawn(
    process.execPath,
    workerArguments(service, runtime, stateDirectory, environmentFile),
    {
      cwd: rootDirectory,
      env: {
        ...localCloudflareEnvironment(),
        NO_COLOR: "1",
        WRANGLER_LOG_PATH: logDirectory
      },
      stdio: ["ignore", "pipe", "pipe"]
    }
  );

  child.stdout.on("data", (buffer) => {
    prefixedOutput(service, buffer, process.stdout, recentOutput, quiet);
  });
  child.stderr.on("data", (buffer) => {
    prefixedOutput(service, buffer, process.stderr, recentOutput, quiet);
  });

  return { child, label: service, recentOutput };
}

function createRuntimeFetch(readinessHeaders, fetchImplementation = fetch) {
  return (url, init = {}) => {
    const headers = new Headers(init.headers);
    for (const [name, value] of Object.entries(readinessHeaders)) {
      headers.set(name, value);
    }
    return fetchImplementation(url, { ...init, headers });
  };
}

async function waitForHealth(worker, origin, path, fetchImplementation) {
  const deadline = Date.now() + startupTimeoutMilliseconds;
  let lastError = "No request attempted";

  while (Date.now() < deadline) {
    if (worker.child.exitCode !== null) {
      throw new Error(
        `${worker.label} Wrangler exited before readiness.\n${worker.recentOutput.join("")}`
      );
    }

    try {
      const response = await fetchImplementation(new URL(path, origin), {
        redirect: "manual",
        signal: AbortSignal.timeout(5_000)
      });
      if (response.status === 200) {
        return;
      }
      lastError = `Health check returned ${response.status}`;
    } catch (error) {
      lastError = String(error);
    }

    await new Promise((resolvePromise) => setTimeout(resolvePromise, 400));
  }

  throw new Error(
    `Timed out waiting for ${worker.label} at ${origin}. Last error: ${lastError}\n` +
      worker.recentOutput.join("")
  );
}

async function stopWorker(worker) {
  if (worker.child.exitCode !== null) {
    return;
  }

  worker.child.kill("SIGTERM");
  await Promise.race([
    new Promise((resolvePromise) => worker.child.once("exit", resolvePromise)),
    new Promise((resolvePromise) =>
      setTimeout(() => {
        if (worker.child.exitCode === null) {
          worker.child.kill("SIGKILL");
        }
        resolvePromise();
      }, 5_000)
    )
  ]);
}

function waitForStopOrExit(workers) {
  return new Promise((resolvePromise, rejectPromise) => {
    const signalHandlers = new Map();
    const cleanup = () => {
      for (const [signal, handler] of signalHandlers) {
        process.off(signal, handler);
      }
    };

    for (const signal of ["SIGINT", "SIGTERM"]) {
      const handler = () => {
        cleanup();
        resolvePromise();
      };
      signalHandlers.set(signal, handler);
      process.once(signal, handler);
    }

    for (const worker of workers) {
      worker.child.once("exit", (code, signal) => {
        cleanup();
        rejectPromise(
          new Error(
            `${worker.label} Wrangler stopped unexpectedly ` +
              `(code ${String(code)}, signal ${String(signal)}).\n` +
              worker.recentOutput.join("")
          )
        );
      });
    }
  });
}

export async function runLocalDevelopment(options = {}) {
  const checkOnly = options.checkOnly ?? false;
  const skipBuild = options.skipBuild ?? false;
  const quiet = options.quiet ?? false;
  const ephemeralPreparationKey = options.ephemeralPreparationKey ?? false;
  const runtime = resolveDevelopmentRuntime(options.environment ?? process.env);
  const checkStateDirectory = join(rootDirectory, ".tmp", "local-start-check", "state");
  const stateDirectory = repositoryOwnedStateDirectory(
    options.stateDirectory ?? (checkOnly ? checkStateDirectory : localStateDirectory)
  );
  const workers = [];
  const environmentFile = ephemeralPreparationKey
    ? join(dirname(stateDirectory), "functional.env")
    : null;
  const fetchImplementation = createRuntimeFetch(
    runtime.readinessHeaders,
    options.fetchImplementation
  );

  if (checkOnly) {
    await rm(stateDirectory, { recursive: true, force: true });
  }
  await mkdir(logDirectory, { recursive: true });
  if (environmentFile !== null) {
    await mkdir(dirname(environmentFile), { recursive: true });
    const signingKey =
      typeof ephemeralPreparationKey === "string"
        ? ephemeralPreparationKey
        : randomBytes(32).toString("base64url");
    await writeFile(
      environmentFile,
      `SECRET_PREPARATION_HMAC_KEY=${signingKey}\n` +
        `ABUSE_IP_HMAC_KEY=${randomBytes(32).toString("base64url")}\n`,
      {
        encoding: "utf8",
        mode: 0o600
      }
    );
  }

  try {
    if (!skipBuild) {
      runPnpm(["build"]);
    }

    workers.push(startWorker("functional", runtime, stateDirectory, quiet, environmentFile));
    workers.push(startWorker("marketing", runtime, stateDirectory, quiet, environmentFile));

    await Promise.all([
      waitForHealth(workers[0], runtime.functionalOrigin, "/api/v1/health", fetchImplementation),
      waitForHealth(workers[1], runtime.marketingOrigin, "/_marketing/health", fetchImplementation)
    ]);

    process.stdout.write(`Functional: ${runtime.functionalOrigin}\n`);
    process.stdout.write(`Marketing:  ${runtime.marketingOrigin}\n`);

    if (checkOnly) {
      const result = await runDeliverySmoke({
        fetchImplementation,
        functionalOrigin: runtime.functionalOrigin,
        marketingOrigin: runtime.marketingOrigin,
        originValidator: validateDevelopmentOriginPair,
        timeoutMilliseconds: 10_000
      });
      process.stdout.write(
        `Local environment check passed ${result.checks} route and policy groups.\n`
      );
      return result;
    }

    process.stdout.write("Both local Workers are ready. Press Ctrl+C to stop them.\n");
    await waitForStopOrExit(workers);
    return null;
  } finally {
    await Promise.all(workers.map((worker) => stopWorker(worker)));
    if (environmentFile !== null) {
      await rm(environmentFile, { force: true });
    }
    if (checkOnly) {
      await rm(stateDirectory, { recursive: true, force: true });
    }
  }
}

if (process.argv[1] && import.meta.url === new URL(`file://${process.argv[1]}`).href) {
  const argumentsList = process.argv.slice(2);
  if (
    argumentsList.some((argument) => argument !== "--check") ||
    argumentsList.filter((argument) => argument === "--check").length > 1
  ) {
    throw new Error("Expected no argument or a single --check argument");
  }
  await runLocalDevelopment({ checkOnly: argumentsList.includes("--check") });
}
