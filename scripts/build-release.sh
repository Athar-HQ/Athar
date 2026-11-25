#!/usr/bin/env bash
# Builds athar release archives for all supported platforms.
#
#   scripts/build-release.sh <version> <output dir>
#
# Writes athar_<version>_<os>_<arch>.tar.gz (.zip on Windows) and
# checksums.txt. Used by .github/workflows/release.yml; runs locally too.
set -euo pipefail

version=${1:?usage: build-release.sh <version> <output dir>}
out=${2:?usage: build-release.sh <version> <output dir>}
targets=(linux/amd64 linux/arm64 darwin/amd64 darwin/arm64 windows/amd64 windows/arm64)

root=$(cd "$(dirname "$0")/.." && pwd)
mkdir -p "$out"
out=$(cd "$out" && pwd)
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

for target in "${targets[@]}"; do
  os=${target%/*}
  arch=${target#*/}
  name="athar_${version}_${os}_${arch}"
  exe=athar
  [[ $os == windows ]] && exe=athar.exe

  mkdir -p "$work/$name"
  (cd "$root" && CGO_ENABLED=0 GOOS=$os GOARCH=$arch \
    go build -trimpath -ldflags "-s -w -X main.version=$version" -o "$work/$name/$exe" ./cli/cmd/athar)
  cp "$root/README.md" "$work/$name/"

  if [[ $os == windows ]]; then
    (cd "$work" && zip -qr "$out/$name.zip" "$name")
  else
    tar -C "$work" -czf "$out/$name.tar.gz" "$name"
  fi
  echo "built $name"
done

(cd "$out" && shasum -a 256 athar_"${version}"_* > checksums.txt)
echo "wrote $out/checksums.txt"
