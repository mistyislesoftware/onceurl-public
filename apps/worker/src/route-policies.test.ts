import { describe, expect, it } from "vitest";
import {
  capabilityTransferContentSecurityPolicy,
  classifyFunctionalRoute,
  TURNSTILE_CHALLENGE_CONTENT_SECURITY_POLICY,
  TURNSTILE_ORIGIN
} from "./route-policies";

describe("functional route classification", () => {
  it.each([
    "/s/locator/token",
    "/m/locator/token",
    "/f/a/b",
    "/u/a/b",
    "/r/a/b",
    "/c/a/b",
    "/h/a/b",
    "/ping/a/b"
  ])("classifies %s as a recipient capability route", (path) => {
    expect(classifyFunctionalRoute(path)).toBe("capability");
  });

  it("keeps browser API, application, asset and marketing-boundary paths separate", () => {
    expect(classifyFunctionalRoute("/api/v1/health")).toBe("api");
    expect(classifyFunctionalRoute("/dashboard")).toBe("application");
    expect(classifyFunctionalRoute("/assets/app.js")).toBe("asset");
    expect(classifyFunctionalRoute("/marketing-assets/site.css")).toBe("boundary");
  });

  it.each([
    "/%73/locator/bearer",
    "/s%2Flocator/bearer",
    "/%2573/locator/bearer",
    "/s%252Flocator/bearer",
    "/%/locator/bearer",
    "/S/locator/bearer",
    "/Api/v1/health",
    "/Assets/app.js",
    "/%61pi/v1/health",
    "/%5fmarketing/health",
    "//s/locator/bearer",
    "/s//locator/bearer",
    "/s/../dashboard",
    "/api//v1/health"
  ])("rejects non-canonical reserved path %s at the boundary", (path) => {
    expect(classifyFunctionalRoute(path)).toBe("boundary");
  });

  it.each(["/apiary", "/assets-v2/app.js", "/sensitive", "/dashboard/"])(
    "does not overmatch application path %s",
    (path) => {
      expect(classifyFunctionalRoute(path)).toBe("application");
    }
  );
});

describe("approved future functional-service policy definitions", () => {
  it("confines Turnstile to the exact isolated challenge origin", () => {
    expect(TURNSTILE_CHALLENGE_CONTENT_SECURITY_POLICY).toContain(
      `script-src 'self' ${TURNSTILE_ORIGIN}`
    );
    expect(TURNSTILE_CHALLENGE_CONTENT_SECURITY_POLICY).toContain(`frame-src ${TURNSTILE_ORIGIN}`);
    expect(TURNSTILE_CHALLENGE_CONTENT_SECURITY_POLICY).not.toContain("*");
    expect(TURNSTILE_CHALLENGE_CONTENT_SECURITY_POLICY).toContain(
      `connect-src 'self' ${TURNSTILE_ORIGIN}`
    );
  });

  it("adds only an exact HTTPS R2 transfer origin and rejects broad values", () => {
    expect(
      capabilityTransferContentSecurityPolicy("https://account-id.r2.cloudflarestorage.com")
    ).toContain("connect-src 'self' https://account-id.r2.cloudflarestorage.com");
    expect(
      capabilityTransferContentSecurityPolicy("https://*.r2.cloudflarestorage.com")
    ).toBeNull();
    expect(
      capabilityTransferContentSecurityPolicy("https://account-id.r2.cloudflarestorage.com/path")
    ).toBeNull();
    expect(
      capabilityTransferContentSecurityPolicy("http://account-id.r2.cloudflarestorage.com")
    ).toBeNull();
    expect(capabilityTransferContentSecurityPolicy("https://transfer.example.test")).toBeNull();
  });
});
