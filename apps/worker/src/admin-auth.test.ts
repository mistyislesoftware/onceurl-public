import { describe, expect, it, vi } from "vitest";
import { createAdminVerifier } from "./admin-auth";
import {
  adminTestAssertion,
  adminTestEnv,
  ADMIN_TEST_JWKS,
  ADMIN_TEST_OPERATOR,
  ADMIN_TEST_ISSUER
} from "./testing/admin";

const NOW = 1_800_000_000_000;
function request(assertion?: string) {
  return new Request("http://localhost/internal/admin", {
    headers: assertion === undefined ? {} : { "Cf-Access-Jwt-Assertion": assertion }
  });
}

describe("independent Access assertion and exact operator authorization", () => {
  it.each([
    { name: "missing", token: undefined },
    { name: "malformed", token: "bad.jwt" },
    { name: "algorithm", header: { alg: "HS256" } },
    { name: "issuer", claims: { iss: "https://attacker.invalid" } },
    { name: "audience", claims: { aud: ["other-app"] } },
    { name: "expiry", claims: { exp: NOW / 1000 } },
    { name: "not-before", claims: { nbf: NOW / 1000 + 1 } },
    { name: "missing not-before", claims: { nbf: undefined } },
    { name: "invalid kid", header: { kid: "../untrusted" } },
    { name: "missing kid", header: { kid: undefined } },
    { name: "key URL", header: { jku: "https://attacker.invalid/certs" } },
    { name: "certificate URL", header: { x5u: "https://attacker.invalid/cert" } },
    { name: "non-operator", claims: { email: "other@onceurl.invalid" } },
    { name: "domain lookalike", claims: { email: "operator@onceurl.invalid.attacker.invalid" } },
    { name: "suffix lookalike", claims: { email: "other-operator@onceurl.invalid" } },
    { name: "case differs", claims: { email: "Operator@onceurl.invalid" } },
    { name: "missing signed email", claims: { email: undefined } },
    { name: "session too long", claims: { exp: NOW / 1000 + 901 } }
  ])("denies $name", async (scenario) => {
    const fetcher = vi.fn(() => Promise.resolve(Response.json(ADMIN_TEST_JWKS)));
    const token = "token" in scenario ? scenario.token : await adminTestAssertion(NOW, scenario);
    await expect(
      createAdminVerifier(fetcher)(request(token), adminTestEnv(), NOW)
    ).rejects.toMatchObject({ status: 403 });
    expect(fetcher.mock.calls.length).toBeLessThanOrEqual(1);
  });
  it.each([0, 1])(
    "accepts published current/previous key %i and derives no authority from cookies or edge headers",
    async (keyIndex) => {
      const fetcher = vi.fn(() => Promise.resolve(Response.json(ADMIN_TEST_JWKS)));
      const result = await createAdminVerifier(fetcher)(
        request(await adminTestAssertion(NOW, { keyIndex })),
        adminTestEnv(),
        NOW
      );
      expect(result).toMatchObject({ actor: ADMIN_TEST_OPERATOR, expiresAt: NOW + 900_000 });
      expect(result.session).toHaveLength(43);
      expect(fetcher).toHaveBeenCalledWith(
        `${ADMIN_TEST_ISSUER}/cdn-cgi/access/certs`,
        expect.objectContaining({ redirect: "error" })
      );
      await expect(
        createAdminVerifier(fetcher)(
          new Request("http://localhost/internal/admin", {
            headers: {
              Cookie: "CF_Authorization=forged",
              "Cf-Access-Authenticated-User-Email": ADMIN_TEST_OPERATOR
            }
          }),
          adminTestEnv(),
          NOW
        )
      ).rejects.toMatchObject({ status: 403 });
    }
  );
  it("rejects invalid signatures even with trusted claims and key id", async () => {
    const token = await adminTestAssertion(NOW, {
      keyIndex: 1,
      header: { kid: ADMIN_TEST_JWKS.keys[0]?.kid }
    });
    await expect(
      createAdminVerifier(() => Promise.resolve(Response.json(ADMIN_TEST_JWKS)))(
        request(token),
        adminTestEnv(),
        NOW
      )
    ).rejects.toMatchObject({ status: 403 });
  });
  it.each([true, false])("refreshes an unknown kid once, resolving=%s", async (resolves) => {
    const fetcher = vi
      .fn()
      .mockResolvedValueOnce(Response.json({ keys: [ADMIN_TEST_JWKS.keys[0]] }))
      .mockResolvedValueOnce(Response.json({ keys: [ADMIN_TEST_JWKS.keys[resolves ? 1 : 0]] }));
    const verify = createAdminVerifier(fetcher);
    await verify(request(await adminTestAssertion(NOW)), adminTestEnv(), NOW);
    const outcome = verify(
      request(await adminTestAssertion(NOW, { keyIndex: 1 })),
      adminTestEnv(),
      NOW + 1000
    );
    if (resolves) await expect(outcome).resolves.toMatchObject({ actor: ADMIN_TEST_OPERATOR });
    else await expect(outcome).rejects.toMatchObject({ status: 403 });
    expect(fetcher).toHaveBeenCalledTimes(2);
  });
  it.each([
    "",
    "http://access.invalid",
    "https://access.invalid/path",
    "https://attacker.example",
    "https://access.invalid:444"
  ])("rejects unavailable/malformed trust %s before a key fetch", async (issuer) => {
    const fetcher = vi.fn(() => Promise.resolve(Response.json(ADMIN_TEST_JWKS)));
    await expect(
      createAdminVerifier(fetcher)(
        request(await adminTestAssertion(NOW)),
        { ...adminTestEnv(), ADMIN_ACCESS_ISSUER: issuer },
        NOW
      )
    ).rejects.toMatchObject({ status: 503 });
    expect(fetcher).not.toHaveBeenCalled();
  });
  it.each([undefined, "[]", '["*@onceurl.invalid"]', "not-json"])(
    "rejects absent/unverifiable exact allowlist %s",
    async (operators) => {
      await expect(
        createAdminVerifier(() => Promise.resolve(Response.json(ADMIN_TEST_JWKS)))(
          request(await adminTestAssertion(NOW)),
          { ...adminTestEnv(), ADMIN_OPERATOR_EMAILS: operators },
          NOW
        )
      ).rejects.toMatchObject({ status: 503 });
    }
  );
  it.each(["network", "http", "malformed", "duplicate", "oversized"])(
    "fails closed on unavailable signing state: %s",
    async (failure) => {
      const fetcher = vi.fn(() => {
        if (failure === "network") return Promise.reject(new Error("provider secret detail"));
        if (failure === "http")
          return Promise.resolve(new Response("unavailable", { status: 503 }));
        if (failure === "duplicate")
          return Promise.resolve(
            Response.json({ keys: [ADMIN_TEST_JWKS.keys[0], ADMIN_TEST_JWKS.keys[0]] })
          );
        return Promise.resolve(
          new Response(failure === "oversized" ? "x".repeat(65_537) : "not-json")
        );
      });
      await expect(
        createAdminVerifier(fetcher)(request(await adminTestAssertion(NOW)), adminTestEnv(), NOW)
      ).rejects.toMatchObject({ status: 503, message: "Administrative request unavailable" });
    }
  );
  it("expires cached trust and never accepts stale keys after refresh failure", async () => {
    const fetcher = vi
      .fn()
      .mockResolvedValueOnce(Response.json(ADMIN_TEST_JWKS))
      .mockRejectedValue(new Error("offline"));
    const verify = createAdminVerifier(fetcher);
    const token = await adminTestAssertion(NOW);
    await verify(request(token), adminTestEnv(), NOW);
    await expect(verify(request(token), adminTestEnv(), NOW + 300_000)).rejects.toMatchObject({
      status: 503
    });
    await expect(verify(request(token), adminTestEnv(), NOW + 300_001)).rejects.toMatchObject({
      status: 503
    });
    expect(fetcher).toHaveBeenCalledTimes(3);
  });
});
