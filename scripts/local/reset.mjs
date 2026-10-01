import { lstat, rm } from "node:fs/promises";
import { dirname } from "node:path";
import { assertExactResetTarget, localStateDirectory, rootDirectory } from "./config.mjs";

async function assertNotSymbolicLink(path, label) {
  try {
    const metadata = await lstat(path);
    if (metadata.isSymbolicLink()) {
      throw new Error(`Refusing to reset through a symbolic-link ${label}`);
    }
    return true;
  } catch (error) {
    if (error?.code === "ENOENT") {
      return false;
    }
    throw error;
  }
}

export async function resetLocalState(
  repositoryDirectory = rootDirectory,
  stateDirectory = localStateDirectory
) {
  const target = assertExactResetTarget(repositoryDirectory, stateDirectory);
  const parentExists = await assertNotSymbolicLink(dirname(target), "local state parent");
  if (!parentExists) {
    return target;
  }
  const targetExists = await assertNotSymbolicLink(target, "local state directory");
  if (!targetExists) {
    return target;
  }

  await rm(target, { recursive: true, force: false });
  return target;
}

if (process.argv[1] && import.meta.url === new URL(`file://${process.argv[1]}`).href) {
  if (process.argv.length !== 2) {
    throw new Error("Local reset does not accept arguments");
  }
  const removed = await resetLocalState();
  process.stdout.write(`Removed disposable local state: ${removed}\n`);
}
