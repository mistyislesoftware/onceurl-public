# Publication format v1

The manifest is UTF-8 JSON with recursively lexically sorted object keys, no
whitespace between tokens and exactly one final LF. Arrays retain order; paths
are ASCII relative POSIX paths, ordered lexically. Numbers are safe integers.
No timestamps are needed to reproduce a source snapshot.

Fields: `schemaVersion` (1), `purpose` (`onceurl.publication.v1`),
`canonicalSourceSha` (40 lowercase hex characters), `policyDigest`,
`exporterDigest`, `publicRepository` (`mistyislesoftware/onceurl-public`),
`publicBranch` (`main`), `files` and `exportDigest`.

Each file entry has `path`, `mode` (`100644` or `100755`), `size` in bytes and
`sha256`. `exportDigest` is SHA-256 of the canonical JSON encoding (including LF)
of the complete `files` array. Payload bytes and executable modes are preserved
unless an explicitly reviewed deterministic transformation is specified.
Symlinks, submodules, path traversal and case collisions are prohibited.

The payload list excludes exactly the manifest, `publication/signature.json` and
`publication/verification-key.pem` to avoid recursive hashing. All other tracked
paths must be listed. The detached signature authenticates the complete exact
manifest bytes, including its export digest. The envelope contains schema version
1, algorithm `Ed25519`, SHA-256 `keyFingerprint` of DER SPKI public-key bytes,
SHA-256 `manifestDigest` and standard padded base64 `signature` (64 raw bytes).

The supplied public key is a copy, not a trust anchor. Verifiers must obtain the
expected fingerprint from an independently trusted publication authority. A
snapshot cannot rotate its own signer or verifier. Missing or revoked trust
material fails closed. Cryptographic validity alone does not establish that a
snapshot is the latest accepted publication.

`publicSourceSha` is recorded after commit creation in the trusted publication
ledger and release evidence; it cannot be included in the tree of its own commit.
The ledger binds it to `canonicalSourceSha`, `exportDigest`, manifest digest and
a monotonic publication sequence. Replaying an old valid signature does not
authorize another publication or deployment.

No private source access is necessary to verify a published signature and tree.
Content-only checking of an unsigned review candidate is not provenance approval.
