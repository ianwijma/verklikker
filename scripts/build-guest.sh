#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
case "$(uname -m)" in x86_64) task_arch=x64; docker_arch=amd64;; aarch64|arm64) task_arch=arm64; docker_arch=arm64;; *) exit 1;; esac
TRACEE_IMAGE=${TRACEE_IMAGE:-aquasec/tracee@sha256:cfbbfee972e64a644f6b1bac74ee26998e6e12442697be4c797ae563553a2a5b}
case "$TRACEE_IMAGE" in aquasec/tracee@sha256:*) ;; *) echo 'TRACEE_IMAGE must be pinned by digest' >&2; exit 1;; esac
mkdir -p runtime/build-inputs "runtime/$task_arch"
docker build -f images/base.Dockerfile -t verklikker/base:local .
docker build -f images/npm.Dockerfile -t verklikker/npm:local .
docker pull "$TRACEE_IMAGE"
docker save -o runtime/build-inputs/base.tar verklikker/base:local
docker save -o runtime/build-inputs/npm.tar verklikker/npm:local
docker tag "$TRACEE_IMAGE" verklikker/tracee:runtime
docker save -o runtime/build-inputs/tracee.tar verklikker/tracee:runtime
printf '%s\n' "$TRACEE_IMAGE" > runtime/build-inputs/tracee-image
docker buildx build --platform "linux/$docker_arch" -f images/guest.Dockerfile --output "type=local,dest=runtime/$task_arch" .
node scripts/runtime-manifest.mjs "$task_arch" "$TRACEE_IMAGE"
cp native/proxy.py runtime/proxy.py
