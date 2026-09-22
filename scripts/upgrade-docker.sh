#!/usr/bin/env sh
set -eu

[ -f .env ] || { printf '%s\n' 'Missing .env; preserve the existing bootstrap credentials.' >&2; exit 1; }
exec docker compose pull && docker compose up -d --build && docker image prune -f
