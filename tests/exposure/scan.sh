#!/usr/bin/env sh
set -eu

# Both tools are load-bearing: `nc` for the port assertions, `curl` for the "this path must
# not be served" HTTP assertions. A scanner image without curl would report the store-file
# check as passing when it never ran — a false negative on the exact thing the test exists
# to catch. Fail loudly rather than silently green.
for tool in nc curl; do
  command -v "$tool" >/dev/null 2>&1 || {
    printf 'required scanner tool missing: %s\n' "$tool" >&2
    exit 2
  }
done

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

# A backup bundle fetchable over the public listener would expose every credential the
# product holds (channel secrets, 2FA secrets, the audit trail). It must not resolve.
if curl --silent --show-error --fail --max-time 3 "http://${host}/var/lib/pingap/backups/"; then
  printf 'backup directory was served over HTTP\n' >&2
  exit 1
fi

# prometheus_metrics is a per-server path; nothing structurally prevents it landing on the
# public data-plane server, so assert rather than assume it does not answer there.
if curl --silent --show-error --fail --max-time 3 "http://${host}/metrics"; then
  printf 'metrics path answered on the public listener\n' >&2
  exit 1
fi
