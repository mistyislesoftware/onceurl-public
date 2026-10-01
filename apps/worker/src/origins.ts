import type { WorkerEnv } from "./env";

export type OriginEnvironment = Pick<
  WorkerEnv,
  "DEPLOYMENT_ENVIRONMENT" | "MARKETING_ORIGIN" | "FUNCTIONAL_ORIGIN"
>;

export type OriginConfiguration = {
  deploymentEnvironment: string;
  marketingOrigin: string;
  functionalOrigin: string;
};

const DEPLOYMENT_ENVIRONMENTS = new Set(["local", "preview", "staging", "production"]);

function isLoopbackHostname(hostname: string): boolean {
  if (hostname === "localhost" || hostname === "[::1]") {
    return true;
  }

  const octets = hostname.split(".");
  return (
    octets.length === 4 &&
    octets[0] === "127" &&
    octets.every((octet) => /^(?:0|[1-9][0-9]{0,2})$/u.test(octet) && Number(octet) <= 255)
  );
}

function parseExactOrigin(value: string, allowLoopbackHttp: boolean): URL | null {
  try {
    const url = new URL(value);
    const protocolIsAllowed =
      url.protocol === "https:" ||
      (allowLoopbackHttp && url.protocol === "http:" && isLoopbackHostname(url.hostname));

    if (
      !protocolIsAllowed ||
      value !== url.origin ||
      url.hostname.endsWith(".") ||
      url.username !== "" ||
      url.password !== "" ||
      url.pathname !== "/" ||
      url.search !== "" ||
      url.hash !== ""
    ) {
      return null;
    }

    return url;
  } catch {
    return null;
  }
}

export function readOriginConfiguration(env: OriginEnvironment): OriginConfiguration | null {
  if (!DEPLOYMENT_ENVIRONMENTS.has(env.DEPLOYMENT_ENVIRONMENT)) {
    return null;
  }

  const allowLoopbackHttp = env.DEPLOYMENT_ENVIRONMENT === "local";
  const marketing = parseExactOrigin(env.MARKETING_ORIGIN, allowLoopbackHttp);
  const functional = parseExactOrigin(env.FUNCTIONAL_ORIGIN, allowLoopbackHttp);

  if (marketing === null || functional === null || marketing.hostname === functional.hostname) {
    return null;
  }

  return {
    deploymentEnvironment: env.DEPLOYMENT_ENVIRONMENT,
    marketingOrigin: marketing.origin,
    functionalOrigin: functional.origin
  };
}
