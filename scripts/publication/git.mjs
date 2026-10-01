import { execFileSync } from "node:child_process";
import { devNull } from "node:os";
import { assert, SHA, safePath } from "./contract.mjs";

export function git(root, args, input) {
  // Resolve only the explicit checkout (including Git's native linked-worktree file).
  // Never inherit directory/object/ref/index/config overrides or replacement settings.
  const env = Object.fromEntries(
    Object.entries(process.env).filter(([name]) => !/^GIT_/iu.test(name))
  );
  env.GIT_NO_REPLACE_OBJECTS = "1";
  env.GIT_CONFIG_NOSYSTEM = "1";
  // Git for Windows accepts NUL, not Node's Win32 device-path spelling.
  env.GIT_CONFIG_GLOBAL = process.platform === "win32" ? "NUL" : devNull;
  return execFileSync("git", ["--no-replace-objects", "-C", root, ...args], {
    env,
    input,
    maxBuffer: 40_000_000
  });
}
export function readTree(root, sha) {
  SHA.parse(sha);
  const listing = git(root, ["ls-tree", "-rz", "--full-tree", sha]).toString("utf8");
  const records = listing
    .split("\0")
    .filter(Boolean)
    .map((line) => {
      const match = /^(100644|100755) blob ([a-f0-9]{40})\t(.+)$/u.exec(line);
      assert(match, "Symlinks, submodules and special modes are prohibited");
      return { mode: match[1], sha: match[2], path: safePath(match[3]) };
    });
  assert(
    new Set(records.map((r) => r.path.toLowerCase())).size === records.length,
    "Case collision"
  );
  const batch = git(root, ["cat-file", "--batch"], records.map((r) => r.sha).join("\n") + "\n");
  let offset = 0;
  return new Map(
    records.map((record) => {
      const end = batch.indexOf(10, offset);
      const header = batch.subarray(offset, end).toString("ascii").split(" ");
      assert(header[0] === record.sha && header[1] === "blob", "Invalid Git object response");
      const size = Number(header[2]);
      assert(Number.isSafeInteger(size) && size >= 0 && size <= 10_000_000, "Oversized blob");
      const bytes = batch.subarray(end + 1, end + 1 + size);
      offset = end + 2 + size;
      return [record.path, { ...record, bytes }];
    })
  );
}
