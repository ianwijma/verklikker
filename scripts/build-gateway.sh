#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
revision=1cd3f0426b07b3a683d47c671edff8ca261225db
target=native/gateway/upstream
if [ ! -d "$target/.git" ]; then git clone https://github.com/containers/gvisor-tap-vsock.git "$target"; fi
git -C "$target" checkout --detach "$revision"
git -C "$target" restore pkg go.mod go.sum
python3 native/gateway/prepare.py "$target"
mkdir -p "$target/cmd/verklikker-gateway" runtime
cp native/gateway/main.go "$target/cmd/verklikker-gateway/main.go"
destination="$(pwd)/runtime/verklikker-gateway"
cd "$target"
go build -mod=mod -trimpath -o "$destination" ./cmd/verklikker-gateway
