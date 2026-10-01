import { describe, expect, it } from "vitest";
import { accessCodeChallengeFromDetails } from "./turnstile-challenge";

const ACCESS_TICKET = `chl2_a_1_${"A".repeat(22)}_${"B".repeat(43)}`;

describe("Turnstile challenge tickets", () => {
  it("accepts only a bounded access-code ticket from verification-required details", () => {
    expect(
      accessCodeChallengeFromDetails({
        challenge_id: ACCESS_TICKET,
        expires_in_seconds: 300
      })
    ).toEqual({ id: ACCESS_TICKET, action: "onceurl_access_code" });

    for (const details of [
      { challenge_id: `chl2_p_1_${"A".repeat(22)}_${"B".repeat(43)}`, expires_in_seconds: 300 },
      { challenge_id: ACCESS_TICKET, expires_in_seconds: 301 },
      { challenge_id: ACCESS_TICKET, expires_in_seconds: 300, locator: "forbidden" },
      null
    ]) {
      expect(accessCodeChallengeFromDetails(details)).toBeNull();
    }
  });
});
