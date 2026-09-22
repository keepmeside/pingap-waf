#!/usr/bin/env sh
set -eu

host="${EXPOSURE_HOST:-pingap}"
for port in 80 443; do
  nc -z -w 3 "$host" "$port" || {
    printf 'expected port %s to be reachable\n' "$port" >&2
    exit 1
  }
done

for port in 2379 3018 6190 9090; do
  if nc -z -w 1 "$host" "$port" 2>/dev/null; then
    printf 'unexpected exposed port %s\n' "$port" >&2
    exit 1
  fi
done

if curl --silent --show-error --fail --max-time 3 "http://${host}/var/lib/pingap/control-plane.db"; then
  printf 'store file was served over HTTP\n' >&2
  exit 1
fi
