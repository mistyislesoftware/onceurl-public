import { readFileSync, readdirSync, lstatSync } from "node:fs";
import { join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import {
  assert,
  digest,
  MANIFEST_PATH,
  SIGNATURE_PATH,
  PUBLIC_KEY_PATH,
  parseManifest,
  scanPublicContent,
  verifyProvenance
} from "./contract.mjs";
import { git, readTree } from "./git.mjs";

export function verifyTree(tree, { requireSignature = true, trustedFingerprint } = {}) {
  const manifestBytes = tree.get(MANIFEST_PATH)?.bytes;
  assert(manifestBytes, "Missing manifest");
  const manifest = parseManifest(manifestBytes);
  const envelopes = [MANIFEST_PATH];
  const signature = tree.get(SIGNATURE_PATH);
  const key = tree.get(PUBLIC_KEY_PATH);
  assert(Boolean(signature) === Boolean(key), "Incomplete provenance envelope");
  if (signature) {
    assert(signature.mode === "100644" && key.mode === "100644", "Invalid envelope modes");
    envelopes.push(SIGNATURE_PATH, PUBLIC_KEY_PATH);
    if (requireSignature)
      verifyProvenance(manifestBytes, signature.bytes, key.bytes, trustedFingerprint);
  } else assert(!requireSignature, "Unsigned export is not a publication");
  assert(tree.get(MANIFEST_PATH).mode === "100644", "Invalid manifest mode");
  const expectedPaths = [...manifest.files.map((f) => f.path), ...envelopes].sort();
  assert(
    JSON.stringify([...tree.keys()].sort()) === JSON.stringify(expectedPaths),
    "Unexpected or missing public path"
  );
  for (const file of manifest.files) {
    const actual = tree.get(file.path);
    assert(
      actual.mode === file.mode &&
        actual.bytes.length === file.size &&
        digest(actual.bytes) === file.sha256,
      `Public file mismatch: ${file.path}`
    );
    scanPublicContent(file.path, actual.bytes);
  }
  return manifest;
}

export function readDirectory(root) {
  const tree = new Map();
  function walk(prefix = "") {
    for (const entry of readdirSync(join(root, prefix), { withFileTypes: true })) {
      const path = prefix ? `${prefix}/${entry.name}` : entry.name;
      const stat = lstatSync(join(root, path));
      assert(!stat.isSymbolicLink(), "Symlinks prohibited");
      if (entry.isDirectory()) walk(path);
      else {
        assert(stat.isFile(), "Special files prohibited");
        tree.set(path, {
          bytes: readFileSync(join(root, path)),
          mode: stat.mode & 0o111 ? "100755" : "100644"
        });
      }
    }
  }
  walk();
  return tree;
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const mode = process.argv[2];
  assert(["content", "provenance"].includes(mode), "Select content or provenance verification");
  const sha = process.env.PUBLIC_SOURCE_SHA;
  const head = git(process.cwd(), ["rev-parse", "HEAD"]).toString("utf8").trim();
  assert(!sha || sha === head, "Public checkout SHA mismatch");
  const manifest = verifyTree(readTree(process.cwd(), head), {
    requireSignature: mode === "provenance",
    trustedFingerprint: process.env.PUBLICATION_KEY_FINGERPRINT
  });
  process.stdout.write(`${mode} verified: ${manifest.exportDigest}\n`);
}
