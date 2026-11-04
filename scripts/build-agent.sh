#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
mkdir -p "$ROOT/dist"
cd "$ROOT/agent"
CGO_ENABLED=0 go build -trimpath -ldflags='-s -w' -o "$ROOT/dist/privora-agent" ./cmd/privora-agent
(cd "$ROOT/dist" && sha256sum privora-agent) | tee "$ROOT/dist/privora-agent.sha256"
