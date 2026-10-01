import { describe, expect, it, vi } from "vitest";
import { createTestPreparationHmacKey } from "./testing/env";
import {
  CREATION_COMPLETION_WINDOW_MS,
  SecretPreparationConfigurationError,
  createSecretPreparationProof,
  parseSecretPreparationRequest,
  prepareSecretCreation,
  validateSecretCompletion,
  type SecretPreparationProofMaterial
} from "./secret-creation";

const NOW = Date.parse("2026-08-01T12:00:00.000Z");
const SIGNING_KEY_VALUE = createTestPreparationHmacKey();
const SIGNING_KEY = { current: SIGNING_KEY_VALUE } as const;

describe("anonymous secret preparation and completion", () => {
  it("creates bounded signed material with independent route authority and no persistence payload", async () => {
    const prepared = await deterministicPreparation();

    expect(prepared).toMatchObject({
      policy: {
        kind: "secret",
        expires_at: "2026-08-02T12:00:00.000Z",
        max_consumptions: 1,
        reactivation: "forbidden"
      },
      complete_by: "2026-08-01T12:15:00.000Z"
    });
    expect(prepared.creation.operation_id).toMatch(/^op1_[A-Za-z0-9_-]{43}$/u);
    expect(prepared.creation.capability_id).toMatch(/^cap1_[0-9a-f]{48}$/u);
    expect(prepared.creation.locator).toMatch(/^loc1_[0-9a-f]{48}$/u);
    expect(prepared.creation.policy_hash).toMatch(/^[A-Za-z0-9_-]{43}$/u);
    expect(prepared.creation.public_bearer).toMatch(/^pub1_[A-Za-z0-9_-]{43}$/u);
    expect(prepared.creation.owner_bearer).toMatch(/^own1_[A-Za-z0-9_-]{43}$/u);
    expect(prepared.creation.public_bearer.slice(5)).not.toBe(
      prepared.creation.owner_bearer.slice(5)
    );
    expect(prepared.preparation_proof).toMatch(/^prep1_[A-Za-z0-9_-]{43}$/u);
    expect(prepared.creation.access_code_verifier).toBeUndefined();
    expect(JSON.stringify(prepared)).not.toContain("ciphertext");
    expect(JSON.stringify(prepared)).not.toContain("#k=");
  });

  it("canonicalizes fixed typed members rather than signing caller serialization order", async () => {
    const prepared = await deterministicPreparation();
    const reordered = {
      complete_by: prepared.complete_by,
      policy: {
        post_consumption: {
          retention: { mode: prepared.policy.post_consumption.retention.mode },
          behavior: prepared.policy.post_consumption.behavior
        },
        reactivation: prepared.policy.reactivation,
        max_consumptions: prepared.policy.max_consumptions,
        expires_at: prepared.policy.expires_at,
        kind: prepared.policy.kind
      },
      creation: {
        owner_bearer: prepared.creation.owner_bearer,
        public_bearer: prepared.creation.public_bearer,
        policy_hash: prepared.creation.policy_hash,
        created_at: prepared.creation.created_at,
        locator: prepared.creation.locator,
        capability_id: prepared.creation.capability_id,
        operation_id: prepared.creation.operation_id
      }
    } as SecretPreparationProofMaterial;

    await expect(createSecretPreparationProof(reordered, SIGNING_KEY_VALUE)).resolves.toBe(
      prepared.preparation_proof
    );
  });

  it("revalidates the signed descriptor, policy, deadline, idempotency, AD, and hashes", async () => {
    const prepared = await deterministicPreparation();
    const body = completionBody(prepared);
    const validated = await validateSecretCompletion(
      body,
      prepared.creation.operation_id,
      NOW + 1_000,
      SIGNING_KEY
    );

    expect(validated).toMatchObject({
      operationId: prepared.creation.operation_id,
      capabilityId: prepared.creation.capability_id,
      locator: prepared.creation.locator,
      createdAt: prepared.creation.created_at,
      policyHash: prepared.creation.policy_hash,
      recipientPath: `/s/${prepared.creation.locator}/${prepared.creation.public_bearer}`,
      ownerPath: `/m/${prepared.creation.locator}/${prepared.creation.owner_bearer}`,
      expiresAt: prepared.policy.expires_at,
      policy: {
        kind: "secret",
        maxConsumptions: 1,
        reactivation: "forbidden"
      }
    });
    expect(validated?.publicBearerSecretHash).toMatch(/^bh1_[A-Za-z0-9_-]{43}$/u);
    expect(validated?.ownerBearerSecretHash).toMatch(/^bh1_[A-Za-z0-9_-]{43}$/u);
    expect(validated?.publicBearerSecretHash).not.toBe(validated?.ownerBearerSecretHash);
    expect(validated?.accessCodeVerifier).toBeNull();
  });

  it("binds an optional browser-derived access-code verifier into the preparation proof", async () => {
    const verifier = {
      version: "acv1",
      algorithm: "PBKDF2-SHA-256",
      iterations: 210_000,
      salt: "AAAAAAAAAAAAAAAAAAAAAA",
      digest: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
    } as const;
    let byte = 0;
    const prepared = await prepareSecretCreation(
      86_400,
      NOW,
      SIGNING_KEY,
      (length) => new Uint8Array(length).fill((byte += 1)),
      verifier
    );
    const body = completionBody(prepared);
    await expect(
      validateSecretCompletion(body, prepared.creation.operation_id, NOW + 1_000, SIGNING_KEY)
    ).resolves.toMatchObject({ accessCodeVerifier: verifier });
    await expect(
      validateSecretCompletion(
        {
          ...body,
          creation: {
            ...body.creation,
            access_code_verifier: { ...verifier, digest: `B${verifier.digest.slice(1)}` }
          }
        },
        prepared.creation.operation_id,
        NOW + 1_000,
        SIGNING_KEY
      )
    ).resolves.toBeNull();
  });

  it("rejects absent, malformed, non-canonical, unsupported, truncated, extended, and altered proofs", async () => {
    const prepared = await deterministicPreparation();
    const body = completionBody(prepared);
    const payload = prepared.preparation_proof.slice("prep1_".length);
    const alteredCharacter = payload[0] === "A" ? "C" : "A";
    const cases: unknown[] = [
      omit(body, "preparation_proof"),
      { ...body, preparation_proof: "malformed" },
      { ...body, preparation_proof: `prep1_${payload.slice(0, -1)}B` },
      { ...body, preparation_proof: `prep2_${payload}` },
      { ...body, preparation_proof: prepared.preparation_proof.slice(0, -1) },
      { ...body, preparation_proof: `${prepared.preparation_proof}A` },
      {
        ...body,
        preparation_proof: `prep1_${alteredCharacter}${payload.slice(1)}`
      }
    ];

    for (const candidate of cases) {
      await expect(
        validateSecretCompletion(
          candidate,
          prepared.creation.operation_id,
          NOW + 1_000,
          SIGNING_KEY
        )
      ).resolves.toBeNull();
    }
  });

  it("authenticates every creation descriptor field", async () => {
    const prepared = await deterministicPreparation();
    const mutations: Record<string, string> = {
      operation_id: `op1_${base64urlBytes(31)}`,
      capability_id: `cap1_${"d".repeat(48)}`,
      locator: `loc1_${"e".repeat(48)}`,
      created_at: "2026-08-01T12:00:00.001Z",
      policy_hash: base64urlBytes(32),
      public_bearer: `pub1_${base64urlBytes(33)}`,
      owner_bearer: `own1_${base64urlBytes(34)}`
    };

    for (const [field, value] of Object.entries(mutations)) {
      const body = completionBody(prepared);
      const candidate = {
        ...body,
        creation: { ...body.creation, [field]: value }
      };
      await expect(
        validateSecretCompletion(
          candidate,
          field === "operation_id" ? value : prepared.creation.operation_id,
          NOW + 1_000,
          SIGNING_KEY
        )
      ).resolves.toBeNull();
    }
  });

  it("authenticates every public policy field and complete_by", async () => {
    const prepared = await deterministicPreparation();
    const body = completionBody(prepared);
    const policies = [
      { ...body.policy, kind: "file" },
      { ...body.policy, expires_at: "2026-08-02T13:00:00.000Z" },
      { ...body.policy, max_consumptions: 2 },
      { ...body.policy, reactivation: "allowed" },
      {
        ...body.policy,
        post_consumption: { ...body.policy.post_consumption, behavior: "delete" }
      },
      {
        ...body.policy,
        post_consumption: {
          ...body.policy.post_consumption,
          retention: { mode: "immediate" }
        }
      }
    ];

    for (const policy of policies) {
      await expect(
        validateSecretCompletion(
          { ...body, policy },
          prepared.creation.operation_id,
          NOW + 1_000,
          SIGNING_KEY
        )
      ).resolves.toBeNull();
    }
    await expect(
      validateSecretCompletion(
        { ...body, complete_by: "2026-08-01T12:15:00.001Z" },
        prepared.creation.operation_id,
        NOW + 1_000,
        SIGNING_KEY
      )
    ).resolves.toBeNull();
  });

  it("prevents proof copying across operations, capabilities, locators, policies, and bearer pairs", async () => {
    const prepared = await deterministicPreparation();
    const body = completionBody(prepared);
    const copies = [
      {
        ...body,
        creation: { ...body.creation, operation_id: `op1_${base64urlBytes(41)}` }
      },
      {
        ...body,
        creation: { ...body.creation, capability_id: `cap1_${"b".repeat(48)}` }
      },
      { ...body, creation: { ...body.creation, locator: `loc1_${"b".repeat(48)}` } },
      { ...body, policy: { ...body.policy, expires_at: "2026-08-02T13:00:00.000Z" } },
      {
        ...body,
        creation: {
          ...body.creation,
          public_bearer: `pub1_${base64urlBytes(42)}`,
          owner_bearer: `own1_${base64urlBytes(43)}`
        }
      }
    ];

    for (const candidate of copies) {
      await expect(
        validateSecretCompletion(
          candidate,
          candidate.creation.operation_id,
          NOW + 1_000,
          SIGNING_KEY
        )
      ).resolves.toBeNull();
    }
  });

  it("rejects caller-selected low-entropy bearers and equal decoded bearers even with a valid proof", async () => {
    const prepared = await deterministicPreparation();
    const body = completionBody(prepared);
    const lowEntropy = {
      ...body,
      creation: {
        ...body.creation,
        public_bearer: `pub1_${base64urlBytes(0)}`,
        owner_bearer: `own1_${base64urlBytes(1)}`
      }
    };
    await expect(
      validateSecretCompletion(lowEntropy, prepared.creation.operation_id, NOW + 1_000, SIGNING_KEY)
    ).resolves.toBeNull();

    const equalBody = {
      ...body,
      creation: {
        ...body.creation,
        owner_bearer: `own1_${body.creation.public_bearer.slice("pub1_".length)}`
      }
    };
    const equalMaterial = {
      creation: equalBody.creation,
      policy: equalBody.policy,
      complete_by: equalBody.complete_by
    } as SecretPreparationProofMaterial;
    const equalProof = await createSecretPreparationProof(equalMaterial, SIGNING_KEY_VALUE);
    const hasher = vi.fn();
    await expect(
      validateSecretCompletion(
        { ...equalBody, preparation_proof: equalProof },
        prepared.creation.operation_id,
        NOW + 1_000,
        SIGNING_KEY,
        hasher
      )
    ).resolves.toBeNull();
    expect(hasher).not.toHaveBeenCalled();
  });

  it("validates proof and deadline before bearer hashing", async () => {
    const prepared = await deterministicPreparation();
    const hasher = vi.fn();
    const forged = {
      ...completionBody(prepared),
      preparation_proof: `prep1_${base64urlBytes(99)}`
    };
    await expect(
      validateSecretCompletion(
        forged,
        prepared.creation.operation_id,
        NOW + 1_000,
        SIGNING_KEY,
        hasher
      )
    ).resolves.toBeNull();
    expect(hasher).not.toHaveBeenCalled();

    await expect(
      validateSecretCompletion(
        completionBody(prepared),
        prepared.creation.operation_id,
        NOW + CREATION_COMPLETION_WINDOW_MS + 1,
        SIGNING_KEY,
        hasher
      )
    ).resolves.toBeNull();
    expect(hasher).not.toHaveBeenCalled();
  });

  it("accepts immediately before and exactly at the deadline, then rejects immediately after", async () => {
    const prepared = await deterministicPreparation();
    const body = completionBody(prepared);
    for (const now of [
      NOW + CREATION_COMPLETION_WINDOW_MS - 1,
      NOW + CREATION_COMPLETION_WINDOW_MS
    ]) {
      await expect(
        validateSecretCompletion(body, prepared.creation.operation_id, now, SIGNING_KEY)
      ).resolves.not.toBeNull();
    }
    await expect(
      validateSecretCompletion(
        body,
        prepared.creation.operation_id,
        NOW + CREATION_COMPLETION_WINDOW_MS + 1,
        SIGNING_KEY
      )
    ).resolves.toBeNull();
  });

  it("preserves exact retry with the original proof, descriptor, ciphertext, and operation", async () => {
    const prepared = await deterministicPreparation();
    const body = completionBody(prepared);
    const first = await validateSecretCompletion(
      body,
      prepared.creation.operation_id,
      NOW + 1_000,
      SIGNING_KEY
    );
    const retry = await validateSecretCompletion(
      structuredClone(body),
      prepared.creation.operation_id,
      NOW + 2_000,
      SIGNING_KEY
    );
    expect(retry).toEqual(first);
  });

  it("accepts the previous key only through the preparation deadline during rotation", async () => {
    const prepared = await deterministicPreparation();
    const body = completionBody(prepared);
    const rotatedKey = createTestPreparationHmacKey();
    const rotatedKeys = { current: rotatedKey, previous: SIGNING_KEY_VALUE } as const;

    await expect(
      validateSecretCompletion(body, prepared.creation.operation_id, NOW + 1_000, rotatedKeys)
    ).resolves.not.toBeNull();
    await expect(
      validateSecretCompletion(
        body,
        prepared.creation.operation_id,
        NOW + CREATION_COMPLETION_WINDOW_MS,
        rotatedKeys
      )
    ).resolves.not.toBeNull();
    await expect(
      validateSecretCompletion(body, prepared.creation.operation_id, NOW + 1_000, {
        current: rotatedKey
      })
    ).resolves.toBeNull();
    await expect(
      validateSecretCompletion(
        body,
        prepared.creation.operation_id,
        NOW + CREATION_COMPLETION_WINDOW_MS + 1,
        rotatedKeys
      )
    ).resolves.toBeNull();
    await expect(
      validateSecretCompletion(
        body,
        prepared.creation.operation_id,
        NOW + CREATION_COMPLETION_WINDOW_MS + 1,
        { current: rotatedKey }
      )
    ).resolves.toBeNull();

    const nextPrepared = await deterministicPreparation(rotatedKey);
    const nextBody = completionBody(nextPrepared);
    await expect(
      validateSecretCompletion(nextBody, nextPrepared.creation.operation_id, NOW + 1_000, {
        current: SIGNING_KEY_VALUE
      })
    ).resolves.toBeNull();
    await expect(
      validateSecretCompletion(
        nextBody,
        nextPrepared.creation.operation_id,
        NOW + 1_000,
        rotatedKeys
      )
    ).resolves.not.toBeNull();
  });

  it("fails closed for missing or malformed current and previous signing configuration", async () => {
    const prepared = await deterministicPreparation();
    const body = completionBody(prepared);
    const rotatedKey = createTestPreparationHmacKey();

    for (const invalidKey of ["", "not-canonical", `${base64urlBytes(5)}=`]) {
      await expect(
        validateSecretCompletion(body, prepared.creation.operation_id, NOW + 1_000, {
          current: invalidKey
        })
      ).rejects.toBeInstanceOf(SecretPreparationConfigurationError);
      await expect(
        validateSecretCompletion(body, prepared.creation.operation_id, NOW + 1_000, {
          current: rotatedKey,
          previous: invalidKey
        })
      ).rejects.toBeInstanceOf(SecretPreparationConfigurationError);
    }
    await expect(
      validateSecretCompletion(body, prepared.creation.operation_id, NOW + 1_000, {
        current: undefined as unknown as string
      })
    ).rejects.toBeInstanceOf(SecretPreparationConfigurationError);
    await expect(prepareSecretCreation(86_400, NOW, { current: "" })).rejects.toBeInstanceOf(
      SecretPreparationConfigurationError
    );
    await expect(
      prepareSecretCreation(86_400, NOW, {
        current: SIGNING_KEY_VALUE,
        previous: "malformed-configuration"
      })
    ).rejects.toBeInstanceOf(SecretPreparationConfigurationError);
  });

  it("fails closed when preparation encounters repeatedly equal random bearer values", async () => {
    await expect(
      prepareSecretCreation(86_400, NOW, SIGNING_KEY, (length) => new Uint8Array(length))
    ).rejects.toThrow("Unable to generate independent capability bearer secrets");
  });

  it("rejects unsupported policy, extra fields, idempotency conflicts, and AD mismatches", async () => {
    const prepared = await deterministicPreparation();
    const body = completionBody(prepared);
    const cases: readonly [unknown, string | undefined][] = [
      [{ ...body, extra: true }, prepared.creation.operation_id],
      [body, undefined],
      [body, `op1_${base64urlBytes(77)}`],
      [
        {
          ...body,
          ciphertext_envelope: {
            ...body.ciphertext_envelope,
            ad: { ...body.ciphertext_envelope.ad, locator: `loc1_${"f".repeat(48)}` }
          }
        },
        prepared.creation.operation_id
      ],
      [
        {
          ...body,
          ciphertext_envelope: {
            ...body.ciphertext_envelope,
            ad: {
              createdAt: body.ciphertext_envelope.ad.createdAt,
              capabilityId: body.ciphertext_envelope.ad.capabilityId,
              kind: "secret",
              locator: body.ciphertext_envelope.ad.locator,
              policyHash: body.ciphertext_envelope.ad.policyHash,
              purpose: "onceurl.phase1a.secret-text",
              version: "ouzk-v1"
            }
          }
        },
        prepared.creation.operation_id
      ]
    ];
    for (const [candidate, key] of cases) {
      await expect(
        validateSecretCompletion(candidate, key, NOW + 1_000, SIGNING_KEY)
      ).resolves.toBeNull();
    }
  });

  it("accepts only the four controlled-beta expiry choices", () => {
    const challengeId = `chl2_p_1_${"A".repeat(22)}_${"A".repeat(43)}`;
    for (const seconds of [3_600, 86_400, 604_800, 2_592_000]) {
      expect(
        parseSecretPreparationRequest({ expires_in_seconds: seconds, challenge_id: challengeId })
      ).toEqual({
        expires_in_seconds: seconds,
        challenge_id: challengeId
      });
    }
    for (const value of [0, 60, 86_401, "86400", null, undefined]) {
      expect(
        parseSecretPreparationRequest({ expires_in_seconds: value, challenge_id: challengeId })
      ).toBeNull();
    }
    expect(parseSecretPreparationRequest({ expires_in_seconds: 86_400 })).toBeNull();
    expect(
      parseSecretPreparationRequest({
        expires_in_seconds: 86_400,
        challenge_id: challengeId,
        extra: true
      })
    ).toBeNull();
  });
});

async function deterministicPreparation(signingKey = SIGNING_KEY_VALUE) {
  let byte = 0;
  return prepareSecretCreation(86_400, NOW, { current: signingKey }, (length) => {
    byte += 1;
    return new Uint8Array(length).fill(byte);
  });
}

function completionBody(prepared: Awaited<ReturnType<typeof deterministicPreparation>>) {
  return {
    creation: prepared.creation,
    policy: prepared.policy,
    complete_by: prepared.complete_by,
    preparation_proof: prepared.preparation_proof,
    ciphertext_envelope: {
      version: "ouzk-v1",
      alg: "AES-256-GCM",
      nonce: "AAAAAAAAAAAAAAAA",
      ciphertext: "AAAAAAAAAAAAAAAAAAAAAAA",
      ad: {
        capabilityId: prepared.creation.capability_id,
        createdAt: prepared.creation.created_at,
        kind: "secret",
        locator: prepared.creation.locator,
        policyHash: prepared.creation.policy_hash,
        purpose: "onceurl.phase1a.secret-text",
        version: "ouzk-v1"
      }
    }
  } as const;
}

function base64urlBytes(byte: number): string {
  const bytes = new Uint8Array(32).fill(byte);
  let binary = "";
  for (const value of bytes) binary += String.fromCharCode(value);
  bytes.fill(0);
  return btoa(binary).replaceAll("+", "-").replaceAll("/", "_").replaceAll("=", "");
}

function omit(value: Record<string, unknown>, key: string): Record<string, unknown> {
  return Object.fromEntries(Object.entries(value).filter(([candidate]) => candidate !== key));
}
