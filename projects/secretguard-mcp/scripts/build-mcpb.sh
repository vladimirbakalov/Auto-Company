#!/usr/bin/env bash
# Rebuilds the .mcpb desktop-extension bundle (manifest.json + dist/ + prod
# node_modules) into ./out/secretguard-mcp-<version>.mcpb. Prints the file's
# sha256 at the end — that value goes into server.json's fileSha256 when
# publishing a new version to the MCP Registry or cutting a new GitHub Release.
set -euo pipefail
cd "$(dirname "$0")/.."

VERSION=$(node -p "require('./package.json').version")
STAGE=$(mktemp -d)
trap 'rm -rf "$STAGE"' EXIT

npm run build
cp -r dist "$STAGE/dist"
cp package.json package-lock.json manifest.json "$STAGE/"
(cd "$STAGE" && npm ci --omit=dev --ignore-scripts)

mkdir -p out
npx -y @anthropic-ai/mcpb pack "$STAGE" "out/secretguard-mcp-${VERSION}.mcpb"
shasum -a 256 "out/secretguard-mcp-${VERSION}.mcpb"
