# OnceURL

This repository is a public source mirror. Canonical engineering development occurs elsewhere. Direct commits and pull requests here are not authoritative.

OnceURL implements browser-encrypted, temporary one-time secret capabilities.
Explicit recipient action can release ciphertext at most once; passive requests
never consume it. The browser holds the decryption key. A lost response can mean
the recipient receives nothing even though the secret was consumed.

This is source publication, not an announcement of a public beta or a live service.
Marketing and functional applications have separate origins and deployments.

## Local inspection and validation

Use Node.js 24 (at least 24.11.0) and pnpm 11.13.0.

```sh
pnpm install --frozen-lockfile
pnpm repository-policy:check
pnpm typecheck
pnpm lint
pnpm test
pnpm build
```

`pnpm test:integration` runs local Worker integration coverage.
`pnpm exec playwright install chromium` and `pnpm test:browser` run browser flows.
`pnpm dev:local` starts the functional and marketing applications on distinct
loopback hostnames. Local examples contain synthetic data only.

The workspace contains `apps/web`, `apps/worker`, `apps/marketing` and shared
`packages/`. Public API documentation is in `docs/openapi.yaml`.
Remote configuration is deliberately unconfigured; no deployment workflow or
provider credential is distributed in this foundation.

## Publication provenance

`publication/manifest.json` binds the opaque canonical source revision to every
payload path, file mode, byte count and SHA-256 digest. The manifest and detached
Ed25519 signature use the format documented in `publication/FORMAT.md`.

Verification requires an independently obtained trusted signer fingerprint:

```sh
PUBLICATION_KEY_FINGERPRINT=TRUSTED_SHA256_FINGERPRINT pnpm provenance:check
```

Do not trust a key simply because this snapshot contains it. The trusted publisher
independently authorizes accepted updates; public CI alone is not that authority.

The source is proprietary/all rights reserved. See `LICENSE`, `CONTRIBUTING.md`
and `.github/SECURITY.md`. Third-party dependencies retain their own licences.
