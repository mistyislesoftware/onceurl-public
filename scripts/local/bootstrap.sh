#!/usr/bin/env bash

set -Eeuo pipefail

script_directory="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
repository_directory="$(cd -- "$script_directory/../.." && pwd)"
required_node_major="24"
required_pnpm_version="11.13.0"

cd "$repository_directory"

node_major=""
if command -v node >/dev/null 2>&1; then
  node_major="$(node --version | sed -E 's/^v([0-9]+).*/\1/')"
fi

if [[ "$node_major" != "$required_node_major" ]]; then
  nvm_directory="${NVM_DIR:-$HOME/.nvm}"
  if [[ -s "$nvm_directory/nvm.sh" ]]; then
    export NVM_DIR="$nvm_directory"
    # shellcheck source=/dev/null
    . "$NVM_DIR/nvm.sh"
    nvm install
    nvm use
  else
    echo "OnceURL requires Node 24. Install it from .nvmrc or rebuild the Dev Container." >&2
    exit 1
  fi
fi

if ! command -v corepack >/dev/null 2>&1; then
  echo "Corepack is required to activate the repository-pinned pnpm version." >&2
  exit 1
fi

export COREPACK_ENABLE_DOWNLOAD_PROMPT=0
export TMPDIR=/tmp
export WRANGLER_LOG_PATH="$repository_directory/.tmp/wrangler-logs"
mkdir -p "$WRANGLER_LOG_PATH"

if ! command -v pnpm >/dev/null 2>&1; then
  if ! corepack enable pnpm; then
    echo "Corepack could not create the pnpm shim. Check permissions for the active Node installation." >&2
    exit 1
  fi
fi

actual_pnpm_version="$(pnpm --version)"
if [[ "$actual_pnpm_version" != "$required_pnpm_version" ]]; then
  corepack install --global "pnpm@$required_pnpm_version"
  actual_pnpm_version="$(pnpm --version)"
fi

if [[ "$actual_pnpm_version" != "$required_pnpm_version" ]]; then
  echo "Expected pnpm $required_pnpm_version but found $actual_pnpm_version." >&2
  exit 1
fi

pnpm install --frozen-lockfile
pnpm env:check

echo "OnceURL bootstrap completed."
