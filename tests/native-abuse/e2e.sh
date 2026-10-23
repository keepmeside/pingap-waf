#!/usr/bin/env bash
set -euo pipefail
root="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$root"
image="${PINGAP_CANARY_IMAGE:-pingap-native-canary:phase5-final}"
out="$root/.cross-review/implementation/phase6/e2e.$(date +%Y%m%d%H%M%S).$$"
mkdir -p "$out"
services_before="$(docker ps --format '{{.ID}} {{.Names}} {{.Image}}' | sort)"
printf '%s\n' "$services_before" > "$out/services-before.txt"
run_case() {
  local label="$1"; shift
  printf 'CASE %s\n' "$label" | tee "$out/$label.log"
  PINGAP_CANARY_IMAGE="$image" "$@" 2>&1 | tee -a "$out/$label.log"
}
run_case rate-policy python3 tests/admin/policy-canary.py rate-policy
run_case challenge-secret python3 tests/admin/policy-canary.py challenge-secret
run_case native-scenario python3 tests/admin/native-canary.py native-scenario
run_case native-ban-api python3 tests/admin/native-api-canary.py native-ban-api
run_case native-history-storage python3 tests/admin/native-api-canary.py native-history-storage
run_case native-abuse-browser python3 tests/admin/policy-canary.py native-abuse
services_after="$(docker ps --format '{{.ID}} {{.Names}} {{.Image}}' | sort)"
printf '%s\n' "$services_after" > "$out/services-after.txt"
diff -u "$out/services-before.txt" "$out/services-after.txt"
image_id="$(docker image inspect "$image" --format '{{.Id}}')"
if docker image inspect "$image" --format '{{json .Config.Env}} {{json .Config.Labels}}' | tr '[:upper:]' '[:lower:]' | grep -q crowdsec; then
  echo 'unexpected CrowdSec runtime dependency' >&2
  exit 1
fi
if docker ps --format '{{.Names}} {{.Image}}' | tr '[:upper:]' '[:lower:]' | grep -q crowdsec; then
  echo 'unexpected CrowdSec service' >&2
  exit 1
fi
cat > "$out/result.json" <<JSON
{"image":"$image","image_id":"$image_id","cases":["rate-policy","challenge-secret","native-scenario","native-ban-api","native-history-storage","native-abuse-browser"],"services_unchanged":true,"crowdsec_runtime_dependency":false}
JSON
printf 'NATIVE_ABUSE_E2E_PASS\n'
