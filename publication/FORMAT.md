# Publication formats v1 and v2

The manifest is UTF-8 JSON with recursively lexically sorted object keys, no
whitespace between tokens and exactly one final LF. Arrays retain order; paths
are ASCII relative POSIX paths, ordered lexically. Numbers are safe integers.
No timestamps are needed to reproduce a source snapshot.

Bootstrap fields: `schemaVersion` (1), `purpose` (`onceurl.publication.v1`),
`canonicalSourceSha` (40 lowercase hex characters), `policyDigest`,
`exporterDigest`, `publicRepository` (`mistyislesoftware/onceurl-public`),
`publicBranch` (`main`), `files` and `exportDigest`.

Subsequent publications use `schemaVersion` 2 and purpose
`onceurl.publication.v2`. They retain every bootstrap field and add a signed
`publication` object with `publicationSequence` (integer greater than 1),
`previousAcceptedDigest` (SHA-256 of the exact preceding accepted ledger record),
`previousPublicSourceSha` (the preceding accepted public commit) and
`signerFingerprint` (the independently pinned DER-SPKI fingerprint). Version 1
remains verifiable for the original bootstrap; it cannot authorize a subsequent
controlled publication PR.

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

Sequence-N publication uses a controlled PR whose exact head/tree and sole
accepted public parent are independently checked before merge. The required
authority-issued `publication/accepted` check binds the exact candidate record.
Post-merge reconciliation checks the actual squash commit, unchanged accepted
PR head, identical complete tree, sole expected public parent, current mains
and fresh required CI before advancing the external ledger. Direct public
engineering or an arbitrary same-name check cannot establish acceptance.

The public staging controller separately requires release and campaign
authorizations, each bound to both source identities, export/accepted-record
digests, exact runs/attempts, nonce and a maximum 60-second lifetime. Publication
signatures do not grant deployment authority. The provider runner descriptor
fails closed until a separately reviewed version-2 implementation is available.
Public workflow success alone is not final source acceptance.

No private source access is necessary to verify a published signature and tree.
Content-only checking of an unsigned review candidate is not provenance approval.
