#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
cp native/gateway/main_test.go native/gateway/upstream/cmd/verklikker-gateway/main_test.go
cd native/gateway/upstream
go test -mod=mod -race ./cmd/verklikker-gateway
