import { describe, expect, it } from "vitest";
import {
  parseCloudflareAccountId,
  parseExactHttpsOrigin,
  parsePullRequestNumber,
  previewMetadata,
  previewWorkerNames,
  validateOriginPair
} from "./config.mjs";

describe("delivery configuration", () => {
  it("derives a distinct, reproducible Worker and origin pair for a PR", () => {
    expect(previewMetadata(42, "isolated-account.workers.dev")).toEqual({
      functionalName: "onceurl-pr-42-functional",
      functionalOrigin: "https://onceurl-pr-42-functional.isolated-account.workers.dev",
      marketingName: "onceurl-pr-42-marketing",
      marketingOrigin: "https://onceurl-pr-42-marketing.isolated-account.workers.dev",
      pullRequestNumber: 42,
      workersDevSubdomain: "isolated-account.workers.dev"
    });
  });

  it("rejects malformed PR numbers, account IDs, and Workers.dev subdomains", () => {
    expect(() => parsePullRequestNumber("0")).toThrow(/positive integer/u);
    expect(() => parsePullRequestNumber("1.5")).toThrow(/positive integer/u);
    expect(() => previewWorkerNames("-1")).toThrow(/positive integer/u);
    expect(() => previewMetadata(1, "MixedCase.workers.dev")).toThrow(/lowercase/u);
    expect(() => previewMetadata(1, "nested.account.workers.dev")).toThrow(/one account label/u);
    expect(() => parseCloudflareAccountId("staging-account-id")).toThrow(/32-character/u);
  });

  it("accepts only exact HTTPS deployment origins", () => {
    expect(parseExactHttpsOrigin("https://functional.example", "Functional origin")).toBe(
      "https://functional.example"
    );
    expect(() => parseExactHttpsOrigin("http://functional.example", "Functional origin")).toThrow(
      /HTTPS/u
    );
    expect(() =>
      parseExactHttpsOrigin("https://functional.example/path", "Functional origin")
    ).toThrow(/exact origin/u);
    expect(() =>
      parseExactHttpsOrigin("https://functional.staging.invalid", "Functional origin")
    ).toThrow(/sentinel/u);
  });

  it("rejects origin collapse even when only the port differs", () => {
    expect(() =>
      validateOriginPair("https://same.example:8443", "https://same.example:9443")
    ).toThrow(/different hostnames/u);
  });
});
