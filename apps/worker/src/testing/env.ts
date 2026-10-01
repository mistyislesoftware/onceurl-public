import type { WorkerEnv } from "../env";

type WorkerEnvOverrides = Partial<WorkerEnv>;
type DatabaseBinding = NonNullable<WorkerEnv["DB"]>;
type FilesBinding = NonNullable<WorkerEnv["FILES"]>;
type CapabilityStateBinding = NonNullable<WorkerEnv["CAPABILITY_STATE"]>;
type AbuseControlBinding = NonNullable<WorkerEnv["ABUSE_CONTROL"]>;
type AsyncJobsBinding = NonNullable<WorkerEnv["ASYNC_JOBS"]>;

function unexpectedBindingUse(bindingName: keyof WorkerEnv, operation: string): never {
  throw new Error(
    `Unexpected test use of ${bindingName}.${operation}. Override this binding explicitly.`
  );
}

const defaultAssets: WorkerEnv["ASSETS"] = {
  fetch: () => unexpectedBindingUse("ASSETS", "fetch"),
  connect: () => unexpectedBindingUse("ASSETS", "connect")
};

const defaultDatabase: DatabaseBinding = new Proxy({} as DatabaseBinding, {
  get: (_target, property) => unexpectedBindingUse("DB", String(property))
});

const defaultFiles: FilesBinding = new Proxy({} as FilesBinding, {
  get: (_target, property) => unexpectedBindingUse("FILES", String(property))
});

const defaultCapabilityState: CapabilityStateBinding = new Proxy({} as CapabilityStateBinding, {
  get: (_target, property) => unexpectedBindingUse("CAPABILITY_STATE", String(property))
});

const defaultAbuseControl = {
  getByName: () => ({
    fetch: (request: Request) => {
      const pathname = new URL(request.url).pathname;
      return Promise.resolve(
        Response.json(
          pathname === "/internal/challenge/status" ? { ok: true, verified: true } : { ok: true }
        )
      );
    }
  })
} as unknown as AbuseControlBinding;

const defaultPreparationFloodLimiter: RateLimit = {
  limit: () => Promise.resolve({ success: true })
};

const defaultAsyncJobs: AsyncJobsBinding = new Proxy({} as AsyncJobsBinding, {
  get: (_target, property) => unexpectedBindingUse("ASYNC_JOBS", String(property))
});

export function createTestWorkerEnv(overrides: WorkerEnvOverrides = {}): WorkerEnv {
  return {
    ASSETS: defaultAssets,
    DB: defaultDatabase,
    FILES: defaultFiles,
    CAPABILITY_STATE: defaultCapabilityState,
    ABUSE_CONTROL: defaultAbuseControl,
    PREPARATION_FLOOD_LIMITER: defaultPreparationFloodLimiter,
    ASYNC_JOBS: defaultAsyncJobs,
    DEPLOYMENT_ENVIRONMENT: "local",
    MARKETING_ORIGIN: "http://127.0.0.2",
    FUNCTIONAL_ORIGIN: "http://localhost",
    TURNSTILE_SECRET_KEY: "1x0000000000000000000000000000000AA",
    TURNSTILE_SITE_KEY: "1x00000000000000000000AA",
    ABUSE_IP_HMAC_KEY: createTestPreparationHmacKey(),
    SECRET_PREPARATION_HMAC_KEY: createTestPreparationHmacKey(),
    ...overrides
  };
}

export function createTestPreparationHmacKey(): string {
  const bytes = crypto.getRandomValues(new Uint8Array(32));
  let binary = "";
  for (const byte of bytes) {
    binary += String.fromCharCode(byte);
  }
  bytes.fill(0);
  return btoa(binary).replaceAll("+", "-").replaceAll("/", "_").replaceAll("=", "");
}
