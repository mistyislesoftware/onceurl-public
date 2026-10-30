import { existsSync, mkdtempSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { resolve } from "node:path";
import { describe, expect, it } from "vitest";
import { digest, encode } from "../publication/contract.mjs";
import { providerAdapter, requireReviewedRunner } from "./public-provider.mjs";

const root = resolve(import.meta.dirname, "../..");
const modulePath = "scripts/delivery/staging-provider-v2.mjs";
const descriptorPath = "publication/staging-runner.json";
function reviewed(bytes = Buffer.from("reviewed synthetic module")) {
  const descriptor = {
    schemaVersion: 1,
    contract: "onceurl.staging.provider.v2",
    available: true,
    moduleDigest: digest(bytes)
  };
  return new Map([
    [descriptorPath, { bytes: encode(descriptor), mode: "100644" }],
    [modulePath, { bytes, mode: "100644" }]
  ]);
}
describe("provider descriptor and complete module verification", () => {
  it("matches the complete exported runner bytes and descriptor", () => {
    const bytes = readFileSync(resolve(root, modulePath));
    const template = resolve(root, "publication/templates/staging-runner.json");
    const descriptor = readFileSync(
      existsSync(template) ? template : resolve(root, descriptorPath)
    );
    const tree = reviewed(bytes);
    tree.set(descriptorPath, { bytes: descriptor, mode: "100644" });
    expect(requireReviewedRunner(tree)).toEqual({
      schemaVersion: 1,
      contract: "onceurl.staging.provider.v2",
      available: true,
      moduleDigest: digest(bytes)
    });
  });
  it.each([
    "missing descriptor",
    "missing module",
    "wrong path",
    "descriptor executable",
    "descriptor symlink",
    "module executable",
    "module symlink",
    "digest",
    "unavailable",
    "v1",
    "unknown field"
  ])("fails closed for %s", (kind) => {
    const tree = reviewed();
    const descriptor = JSON.parse(tree.get(descriptorPath).bytes);
    if (kind === "missing descriptor") tree.delete(descriptorPath);
    if (kind === "missing module") tree.delete(modulePath);
    if (kind === "wrong path") {
      tree.set("scripts/delivery/staging-provider-v1.mjs", tree.get(modulePath));
      tree.delete(modulePath);
    }
    if (kind === "descriptor executable") tree.get(descriptorPath).mode = "100755";
    if (kind === "descriptor symlink") tree.get(descriptorPath).mode = "120000";
    if (kind === "module executable") tree.get(modulePath).mode = "100755";
    if (kind === "module symlink") tree.get(modulePath).mode = "120000";
    if (kind === "digest") tree.get(modulePath).bytes = Buffer.from("changed bytes");
    if (kind === "unavailable") descriptor.available = false;
    if (kind === "v1") descriptor.contract = "onceurl.staging.provider.v1";
    if (kind === "unknown field") descriptor.path = "arbitrary-provider.mjs";
    if (["unavailable", "v1", "unknown field"].includes(kind))
      tree.get(descriptorPath).bytes = encode(descriptor);
    expect(() => requireReviewedRunner(tree)).toThrow();
  });
  it("rechecks physical bytes before every adapter operation", async () => {
    mkdirSync(resolve(root, ".tmp"), { recursive: true });
    const directory = mkdtempSync(resolve(root, ".tmp/reviewed-runner-"));
    mkdirSync(resolve(directory, "scripts/delivery"), { recursive: true });
    const bytes = Buffer.from(
      'export const contract="onceurl.staging.provider.v2"; export const preflight=async()=>({passed:true}); export const build=preflight; export const release=preflight; export const campaign=preflight; export const readRelease=preflight; export const readEvidence=preflight;'
    );
    const file = resolve(directory, modulePath);
    writeFileSync(file, bytes);
    const adapter = providerAdapter({ root: directory, tree: reviewed(bytes) });
    await expect(adapter.preflight({})).resolves.toEqual({ passed: true });
    writeFileSync(file, Buffer.from("changed module"));
    for (const method of [
      "preflight",
      "build",
      "release",
      "campaign",
      "readRelease",
      "readEvidence"
    ])
      await expect(adapter[method]({})).rejects.toThrow(/changed after verification/u);
  });
});
