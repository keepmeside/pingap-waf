#!/usr/bin/env bash
set -euo pipefail
root="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$root"
case "${1:-}" in rate-policy|challenge-secret|admin-shell|native-abuse) exec python3 tests/admin/policy-canary.py "$1";; esac
case "${1:-}" in native-ban-api|native-history-storage) exec python3 tests/admin/native-api-canary.py "$1";; esac
case "${1:-}" in native-scenario|policy-unavailable-behaviour|policy-unavailable-limit) exec python3 tests/admin/native-canary.py "$1";; esac
case "${1:-}" in native-capacity) exec python3 tests/admin/native-capacity.py;; esac
case "${1:-}" in policy-save) ;; *) echo "Unsupported canary case: ${1:-missing}" >&2; exit 2;; esac
image="${PINGAP_CANARY_IMAGE:-pingap-native-canary:phase1}"
run_id="pingap-canary-$(date +%s)-$$"
run_dir="$(mktemp -d "$root/.cross-review/implementation/canary.XXXXXX")"
network="$run_id"
sanitize(){
 if [ -d "$run_dir/browser-results" ]; then
  docker run --rm --network none -v "$run_dir/browser-results:/artifacts" node:24-alpine chown -R "$(id -u):$(id -g)" /artifacts
 fi
 python3 tests/admin/sanitize-artifacts.py "$run_dir" "$run_dir/browser-results"
}
cleanup(){
 if [ "$(docker inspect "$run_id" --format '{{index .Config.Labels "pingap.canary"}}' 2>/dev/null || true)" = "$run_id" ]; then
  docker rm -f "$run_id" >/dev/null 2>&1 || true
 fi
 if [ "$(docker network inspect "$network" --format '{{index .Labels "pingap.canary"}}' 2>/dev/null || true)" = "$run_id" ]; then
  docker network rm "$network" >/dev/null 2>&1 || true
 fi
 sanitize
 rm -f "$run_dir/candidate.env" "$run_dir/browser.env"
 # Keep only this run's evidence; never remove another container/network/store.
}
trap cleanup EXIT
mkdir -p "$run_dir/conf" "$run_dir/data" "$run_dir/browser-results"
printf '[basic]\nname = "isolated-admin-canary"\nthreads = 1\n' > "$run_dir/conf/basic.toml"
password="$(python3 -c 'import secrets;print(secrets.token_hex(24))')"
umask 077
printf 'PINGAP_ADMIN_ADDR=0.0.0.0:3018?store=/var/lib/pingap/canary.db\nPINGAP_ADMIN_USER=canary-admin\nPINGAP_ADMIN_PASSWORD=%s\nPINGAP_CONF=/opt/pingap/conf\nPINGAP_AUTORELOAD=true\nPINGAP_DISABLE_ACME=1\n' "$password" > "$run_dir/candidate.env"
printf 'PINGAP_E2E_PASSWORD=%s\nPINGAP_E2E_URL=http://%s:3018\n' "$password" "$run_id" > "$run_dir/browser.env"
unset password
if [ "${PINGAP_CANARY_SKIP_BUILD:-0}" != 1 ]; then
 docker build --label "pingap.canary=true" --tag "$image" . > "$run_dir/build.log" 2>&1
fi
docker image inspect "$image" --format '{{.Id}}' > "$run_dir/image-id.txt"
docker ps --format '{{.ID}} {{.Names}} {{.Image}}' > "$run_dir/services-before.txt"
docker network create --label "pingap.canary=$run_id" "$network" >/dev/null
docker run -d --name "$run_id" --label "pingap.canary=$run_id" --network "$network" --read-only --cpus 2 --memory 1g --tmpfs /tmp:rw,nosuid,nodev,size=64m --env-file "$run_dir/candidate.env" -v "$run_dir/conf:/opt/pingap/conf" -v "$run_dir/data:/var/lib/pingap" "$image" >/dev/null
# Actual browser and real API: source tests run against the candidate, never production.
docker run --rm --label "pingap.canary=$run_id" --network "$network" --env-file "$run_dir/browser.env" -v "$root/web:/source:ro" -v "$run_dir/browser-results:/work/test-results" -w /work mcr.microsoft.com/playwright:v1.64.1-noble bash -c 'set -euo pipefail; tar -C /source --exclude=node_modules --exclude=dist --exclude=test-results --exclude=playwright-report --exclude=.env* --exclude=.npmrc -cf - . | tar -C /work -xf -; npm ci --no-audit --no-fund && npm run test:e2e -- policy-save.spec.ts' > "$run_dir/browser.log" 2>&1 || { docker logs "$run_id" > "$run_dir/candidate.log" 2>&1; sanitize; cat "$run_dir/browser.log"; exit 1; }
docker logs "$run_id" > "$run_dir/candidate.log" 2>&1
docker inspect "$run_id" --format '{{json .State}}' > "$run_dir/state.json"
docker ps --format '{{.ID}} {{.Names}} {{.Image}}' | grep -v " $run_id " > "$run_dir/services-after.txt"
diff -u "$run_dir/services-before.txt" "$run_dir/services-after.txt"
echo ADMIN_POLICY_SAVE_PASS
