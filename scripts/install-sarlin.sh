#!/usr/bin/env bash
set -euo pipefail

target="${1:?usage: install-sarlin.sh <directory>}"
repository="TheRealSarin/sarlin-lang"
asset="sarlin-linux-x86_64.tar.gz"

mkdir -p "$target"
cd "$target"
gh release download --repo "$repository" --pattern "$asset" --pattern "$asset.sha256" --clobber
sha256sum --check "$asset.sha256"
tar -xzf "$asset"
binary="$(find . -type f -name sarlin -perm -u+x | head -n 1)"
if [ -z "$binary" ]; then
  echo "the release archive does not contain a sarlin binary" >&2
  exit 1
fi
chmod +x "$binary"
resolved="$(cd "$(dirname "$binary")" && pwd)/sarlin"
"$resolved" --version
if [ -n "${GITHUB_ENV:-}" ]; then
  echo "SARLIN_BIN=$resolved" >> "$GITHUB_ENV"
fi
