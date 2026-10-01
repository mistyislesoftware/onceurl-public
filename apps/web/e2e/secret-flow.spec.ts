import { expect, test, type Page, type Request, type Route } from "@playwright/test";
import { decodeBase64url, encodeBase64url } from "../src/zero-knowledge";

const marketingHealthUrl = "http://127.0.0.2:8790/_marketing/health";
const browserTestPreparationKey = "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE";
const challengeId = `chl2_p_1_${"A".repeat(22)}_${"A".repeat(43)}`;

interface CreatedSecret {
  readonly recipientUrl: string;
  readonly ownerUrl: string;
}

async function createSecret(
  page: Page,
  plaintext: string,
  accessCode?: string
): Promise<CreatedSecret> {
  await page.goto("/");
  await page.getByLabel("Secret text").fill(plaintext);
  if (accessCode !== undefined) {
    await page.getByLabel("Access code (optional)").fill(accessCode);
  }
  await page.getByLabel("Expiry").selectOption("3600");
  await page.getByRole("button", { name: "Create one-time secret" }).click();
  await expect(
    page.getByRole("heading", { name: "Save both URLs before you leave" })
  ).toBeVisible();
  return {
    recipientUrl: await page.getByLabel("Complete recipient URL").inputValue(),
    ownerUrl: await page.getByLabel("Complete owner management URL").inputValue()
  };
}

test.beforeEach(async ({ page }) => {
  await installCreatorSecurityBoundary(page);
});

async function installCreatorSecurityBoundary(page: Page): Promise<void> {
  await page.route("**/api/v1/challenges", async (route) => {
    await route.fulfill({
      status: 200,
      contentType: "application/json",
      body: JSON.stringify({ challenge_id: challengeId, expires_in_seconds: 300 })
    });
  });
  await page.route("**/api/v1/challenges/status", async (route) => {
    await route.fulfill({
      status: 200,
      contentType: "application/json",
      body: JSON.stringify({ verified: true })
    });
  });
  await page.route("**/api/v1/secrets/prepare", async (route) => {
    const body = JSON.parse(route.request().postData() ?? "{}") as {
      expires_in_seconds?: number;
      challenge_id?: string;
      access_code_verifier?: unknown;
    };
    expect(body.challenge_id).toBe(challengeId);
    expect([3_600, 86_400, 604_800, 2_592_000]).toContain(body.expires_in_seconds);
    const prepared = await createSignedTestPreparation(
      body.expires_in_seconds as 3_600 | 86_400 | 604_800 | 2_592_000,
      Date.now(),
      body.access_code_verifier
    );
    await route.fulfill({
      status: 200,
      contentType: "application/json",
      body: JSON.stringify(prepared)
    });
  });
}

async function createSignedTestPreparation(
  expiresInSeconds: 3_600 | 86_400 | 604_800 | 2_592_000,
  now: number,
  accessCodeVerifier: unknown
) {
  const createdAt = new Date(now).toISOString();
  const policy = {
    kind: "secret" as const,
    expires_at: new Date(now + expiresInSeconds * 1_000).toISOString(),
    max_consumptions: 1 as const,
    reactivation: "forbidden" as const,
    post_consumption: {
      behavior: "retain_capability" as const,
      retention: { mode: "until_expiry" as const }
    }
  };
  const policyHash = encodeBase64url(
    new Uint8Array(
      await crypto.subtle.digest("SHA-256", new TextEncoder().encode(JSON.stringify(policy)))
    )
  );
  const material = {
    creation: {
      operation_id: `op1_${randomBase64url(32)}`,
      capability_id: `cap1_${randomHex(24)}`,
      locator: `loc1_${randomHex(24)}`,
      created_at: createdAt,
      policy_hash: policyHash,
      public_bearer: `pub1_${randomBase64url(32)}`,
      owner_bearer: `own1_${randomBase64url(32)}`,
      ...(accessCodeVerifier === undefined ? {} : { access_code_verifier: accessCodeVerifier })
    },
    policy,
    complete_by: new Date(now + 15 * 60 * 1_000).toISOString()
  };
  const canonical = {
    domain: "onceurl.secret-preparation-proof.v1",
    version: "prep1",
    creation: material.creation,
    policy: material.policy,
    complete_by: material.complete_by
  };
  const key = await crypto.subtle.importKey(
    "raw",
    decodeBase64url(browserTestPreparationKey),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"]
  );
  const signature = await crypto.subtle.sign(
    "HMAC",
    key,
    new TextEncoder().encode(JSON.stringify(canonical))
  );
  return {
    ...material,
    preparation_proof: `prep1_${encodeBase64url(new Uint8Array(signature))}`
  };
}

function randomBase64url(length: number): string {
  return encodeBase64url(crypto.getRandomValues(new Uint8Array(length)));
}

function randomHex(length: number): string {
  return Array.from(crypto.getRandomValues(new Uint8Array(length)), (byte) =>
    byte.toString(16).padStart(2, "0")
  ).join("");
}

function isFunctionalRequest(request: Request): boolean {
  return new URL(request.url()).origin === "http://127.0.0.1:8789";
}

async function commitAndDropCompletionResponse(route: Route): Promise<void> {
  const response = await route.fetch();
  expect(response.status()).toBe(200);
  await route.abort("failed");
}

test("creates, explicitly reveals once, clears, and exposes only coarse owner status", async ({
  page
}) => {
  const plaintext = "real browser secret: snowman ☃";
  const requests: Request[] = [];
  page.on("request", (request) => {
    if (isFunctionalRequest(request)) {
      requests.push(request);
    }
  });

  const created = await createSecret(page, plaintext);
  const recipient = new URL(created.recipientUrl);
  const fragmentKey = recipient.hash.match(/(?:^#|&)k=([^&]+)/u)?.[1];
  expect(fragmentKey).toMatch(/^[A-Za-z0-9_-]{43}$/u);
  expect(new URL(created.ownerUrl).hash).toBe("");

  const serverBoundRequestData = requests.map((request) =>
    JSON.stringify({
      url: request.url(),
      headers: request.headers(),
      body: request.postData() ?? ""
    })
  );
  expect(serverBoundRequestData.join("\n")).not.toContain(plaintext);
  expect(serverBoundRequestData.join("\n")).not.toContain(fragmentKey);
  expect(requests.every((request) => !request.url().includes("#k="))).toBe(true);

  const claims: Request[] = [];
  page.on("request", (request) => {
    if (request.method() === "POST" && new URL(request.url()).pathname.endsWith("/claim")) {
      claims.push(request);
    }
  });
  await page.goto(created.recipientUrl);
  const revealWarning = page.locator("#reveal-risk");
  const revealButton = page.getByRole("button", { name: "Reveal secret once" });
  await expect(revealWarning).toBeVisible();
  await expect(revealWarning).toContainText(
    "before delivery to this browser is confirmed. Keep this page open while it completes"
  );
  await expect(revealButton).toHaveAttribute("aria-describedby", "reveal-risk");
  await expect(revealButton).toBeEnabled();
  expect(claims).toHaveLength(0);

  let releaseClaim!: () => void;
  let markClaimSeen!: () => void;
  const claimGate = new Promise<void>((resolve) => {
    releaseClaim = resolve;
  });
  const claimSeen = new Promise<void>((resolve) => {
    markClaimSeen = resolve;
  });
  await page.route(
    "**/claim",
    async (route) => {
      markClaimSeen();
      await claimGate;
      await route.continue();
    },
    { times: 1 }
  );
  await revealButton.click();
  await claimSeen;
  await expect(page.getByRole("button", { name: "Claiming and decrypting…" })).toBeDisabled();
  await expect(revealWarning).toBeVisible();
  await expect(page.getByText(/no claim was sent/u)).toHaveCount(0);
  releaseClaim();

  const result = page.locator(".secret-result");
  await expect(result).toContainText(plaintext);
  await expect(result).toBeFocused();
  await expect(page.getByText(/no claim was sent/u)).toHaveCount(0);
  expect(new URL(page.url()).hash).toBe("");
  expect(claims).toHaveLength(1);

  const secondClaim = await page.evaluate(async (pathname) => {
    const response = await fetch(`${pathname}/claim`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        operation_id: `reveal_${crypto.randomUUID()}`,
        nonce: `nonce_${crypto.randomUUID()}`
      })
    });
    return { status: response.status, body: await response.text() };
  }, recipient.pathname);
  expect(secondClaim.status).toBe(409);
  expect(secondClaim.body).not.toContain("ciphertext_envelope");
  expect(claims).toHaveLength(2);

  await page.getByRole("button", { name: "Clear and close" }).click();
  await expect(page.getByText(plaintext)).toHaveCount(0);
  await expect(
    page.getByText("The displayed plaintext and in-memory key reference were cleared.")
  ).toBeVisible();
  expect(claims).toHaveLength(2);

  const ownerPath = new URL(created.ownerUrl).pathname;
  const ownerResponsePromise = page.waitForResponse(
    (response) =>
      new URL(response.url()).pathname === ownerPath &&
      response.request().resourceType() === "fetch"
  );
  await page.goto(created.ownerUrl);
  const ownerResponseText = await (await ownerResponsePromise).text();
  await expect(page.getByRole("heading", { name: "Anonymous secret status" })).toBeVisible();
  await expect(page.getByText("Secret created")).toBeVisible();
  await expect(page.getByText("Secret consumed")).toBeVisible();
  const ownerText = await page.locator("body").innerText();
  const claimBody = JSON.parse(claims[0]?.postData() ?? "{}") as {
    operation_id?: string;
    nonce?: string;
  };
  const completionRequest = requests.find(
    (request) =>
      request.method() === "POST" && new URL(request.url()).pathname === "/api/v1/secrets"
  );
  const completionBody = JSON.parse(completionRequest?.postData() ?? "{}") as {
    ciphertext_envelope?: { ciphertext?: string };
  };
  expect(ownerText).not.toContain(plaintext);
  expect(ownerText).not.toContain(fragmentKey);
  expect(ownerResponseText).not.toContain(plaintext);
  expect(ownerResponseText).not.toContain(fragmentKey);
  for (const sensitiveValue of [
    claimBody.operation_id,
    claimBody.nonce,
    completionBody.ciphertext_envelope?.ciphertext
  ]) {
    expect(sensitiveValue).toBeTruthy();
    expect(ownerText).not.toContain(sensitiveValue);
    expect(ownerResponseText).not.toContain(sensitiveValue);
  }
});

test("derives an access-code verifier in the browser and releases only with the raw code", async ({
  page
}) => {
  const plaintext = "browser protected secret";
  const accessCode = "separate channel code";
  const requests: Request[] = [];
  page.on("request", (request) => {
    if (isFunctionalRequest(request)) requests.push(request);
  });

  const created = await createSecret(page, plaintext, accessCode);
  const preparation = requests.find(
    (request) => new URL(request.url()).pathname === "/api/v1/secrets/prepare"
  );
  expect(preparation?.postData()).not.toContain(accessCode);
  expect(preparation?.postData()).toContain('"access_code_verifier"');

  await page.goto(created.recipientUrl);
  await expect(page.getByLabel("Access code")).toBeVisible();
  await page.getByLabel("Access code").fill(accessCode);
  await page.getByRole("button", { name: "Reveal secret once" }).click();
  await expect(page.locator(".secret-result")).toContainText(plaintext);

  const claim = requests.find(
    (request) => request.method() === "POST" && new URL(request.url()).pathname.endsWith("/claim")
  );
  expect(claim?.postData()).toContain(accessCode);
});

test("completion uncertainty survives a rejected recovery and resolves only on exact success", async ({
  page
}) => {
  const plaintext = "monotonic completion uncertainty sentinel";
  const requests: Array<{
    readonly body: string | null;
    readonly idempotencyKey: string | undefined;
  }> = [];
  let completionAttempts = 0;
  await page.route("**/api/v1/secrets", async (route) => {
    completionAttempts += 1;
    requests.push({
      body: route.request().postData(),
      idempotencyKey: route.request().headers()["idempotency-key"]
    });
    if (completionAttempts === 1) {
      await commitAndDropCompletionResponse(route);
      return;
    }
    if (completionAttempts === 2) {
      await route.fulfill({
        status: 400,
        contentType: "application/json",
        body: JSON.stringify({ error: { code: "invalid_request", details: {} } })
      });
      return;
    }
    await route.continue();
  });

  await page.goto("/");
  await page.getByLabel("Secret text").fill(plaintext);
  await page.getByRole("button", { name: "Create one-time secret" }).click();
  await expect(page.getByRole("heading", { name: "Creation outcome unknown" })).toBeVisible();
  await expect(page.getByText(/later error cannot prove/u)).toBeVisible();
  await expect(page.getByLabel("Secret text")).toHaveCount(0);
  await expect(page.getByRole("button", { name: "Create one-time secret" })).toHaveCount(0);

  await page.getByRole("button", { name: "Retry the same encrypted request" }).click();
  await expect.poll(() => completionAttempts).toBe(2);
  await expect(page.getByRole("heading", { name: "Creation outcome unknown" })).toBeVisible();
  await expect(page.getByText("Keep this tab open and do not create a replacement.")).toBeVisible();
  await expect(page.getByText(/check the form and try again/u)).toHaveCount(0);
  await expect(page.getByLabel("Secret text")).toHaveCount(0);

  await page.getByRole("button", { name: "Retry the same encrypted request" }).click();
  await expect(
    page.getByRole("heading", { name: "Save both URLs before you leave" })
  ).toBeVisible();
  expect(completionAttempts).toBe(3);
  expect(requests[0]).toEqual(requests[1]);
  expect(requests[1]).toEqual(requests[2]);

  const recipientUrl = await page.getByLabel("Complete recipient URL").inputValue();
  await page.goto(recipientUrl);
  await page.getByRole("button", { name: "Reveal secret once" }).click();
  await expect(page.locator(".secret-result")).toContainText(plaintext);
});

test("expired completion recovery stays unresolved without offering replacement creation", async ({
  page
}) => {
  await page.clock.install({ time: Date.now() - 24 * 60 * 60 * 1_000 });
  let completionAttempts = 0;
  await page.route("**/api/v1/secrets", async (route) => {
    completionAttempts += 1;
    await commitAndDropCompletionResponse(route);
  });

  await page.goto("/");
  await page.getByLabel("Secret text").fill("expired recovery sentinel");
  await page.getByRole("button", { name: "Create one-time secret" }).click();
  await expect(page.getByRole("heading", { name: "Creation outcome unknown" })).toBeVisible();
  await page.clock.fastForward(16 * 60 * 1_000);

  await expect(
    page.getByText(/authenticated completion recovery interval has ended/u)
  ).toBeVisible();
  await expect(page.getByText(/orphaned duplicate capability may already exist/u)).toBeVisible();
  await expect(page.getByRole("button", { name: "Retry the same encrypted request" })).toHaveCount(
    0
  );
  await expect(page.getByLabel("Secret text")).toHaveCount(0);
  await expect(page.getByRole("button", { name: "Create one-time secret" })).toHaveCount(0);
  expect(completionAttempts).toBe(1);
});

test("a fast creator wall clock cannot suppress exact completion recovery", async ({ page }) => {
  await page.clock.install({ time: Date.now() + 24 * 60 * 60 * 1_000 });
  let completionAttempts = 0;
  await page.route("**/api/v1/secrets", async (route) => {
    completionAttempts += 1;
    await commitAndDropCompletionResponse(route);
  });

  await page.goto("/");
  await page.getByLabel("Secret text").fill("fast wall clock recovery sentinel");
  await page.getByRole("button", { name: "Create one-time secret" }).click();

  await expect(page.getByRole("heading", { name: "Creation outcome unknown" })).toBeVisible();
  await expect(
    page.getByRole("button", { name: "Retry the same encrypted request" })
  ).toBeVisible();
  await expect(page.getByText(/authenticated completion recovery interval has ended/u)).toHaveCount(
    0
  );
  expect(completionAttempts).toBe(1);
});

test("missing and malformed fragments never send a claim", async ({ page, context }) => {
  const created = await createSecret(page, "fragment validation secret");
  const recipientWithoutFragment = new URL(created.recipientUrl);
  recipientWithoutFragment.hash = "";
  const claims: Request[] = [];
  context.on("request", (request) => {
    if (request.method() === "POST" && new URL(request.url()).pathname.endsWith("/claim")) {
      claims.push(request);
    }
  });

  const missingPage = await context.newPage();
  await missingPage.goto(recipientWithoutFragment.toString());
  await expect(missingPage.getByText(/decryption key is missing or invalid/u)).toBeVisible();
  await expect(missingPage.getByRole("button", { name: "Reveal secret once" })).toBeDisabled();

  const malformedPage = await context.newPage();
  const malformed = new URL(recipientWithoutFragment);
  malformed.hash = "#k=not-a-canonical-key&v=ouzk-v1";
  await malformedPage.goto(malformed.toString());
  await expect(malformedPage.getByText(/decryption key is missing or invalid/u)).toBeVisible();
  await expect(malformedPage.getByRole("button", { name: "Reveal secret once" })).toBeDisabled();
  expect(claims).toHaveLength(0);
  await Promise.all([missingPage.close(), malformedPage.close()]);
});

test("navigation away and back cannot restore creator URLs or recipient plaintext", async ({
  page
}) => {
  const creatorPlaintext = "creator bfcache sentinel";
  const created = await createSecret(page, creatorPlaintext);
  await page.goto(marketingHealthUrl);
  await page.goBack();
  await expect(
    page.getByRole("heading", { name: "Share text for one explicit reveal" })
  ).toBeVisible();
  await expect(page.getByLabel("Secret text")).toHaveValue("");
  await expect(page.getByText(created.recipientUrl)).toHaveCount(0);
  await expect(page.getByText(created.ownerUrl)).toHaveCount(0);

  await page.goto(created.recipientUrl);
  await page.getByRole("button", { name: "Reveal secret once" }).click();
  await expect(page.locator(".secret-result")).toContainText(creatorPlaintext);
  await page.goto(marketingHealthUrl);
  await page.goBack();
  await expect(page.getByText(creatorPlaintext)).toHaveCount(0);
  await expect(page.getByText(/decryption key is missing or invalid/u)).toBeVisible();
  expect(new URL(page.url()).hash).toBe("");
});
