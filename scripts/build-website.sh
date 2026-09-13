#!/usr/bin/env bash
# Assemble VitePress content for the docs site under website/.
# English (root locale): crate READMEs + pingap-plugin docs + docs/ + examples/
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
SITE="${ROOT}/website"
EN="${SITE}"

CRATES=(
  util core config discovery health upstream location
  certificate acme cache plugin imageoptim logger
  performance otel sentry pyroscope webhook proxy
)

# --- link rewriting ----------------------------------------------------------

# Strip .md from relative internal links for VitePress cleanUrls.
# Do NOT touch http(s) URLs (e.g. GitHub blob links in source footers).
strip_md_links() {
  local file="$1"
  local tmp
  tmp="$(mktemp)"
  perl -pe '
    s{\(
      (?!https?://)
      ([^)]*?)/README\.md
      (\#[^)]*)?
    \)}{($1/$2)}gx;
    s{\(
      (?!https?://)
      ([^)]+?)\.md
      (\#[^)]*)?
    \)}{($1$2)}gx;
    s{\(([^)]*)/#}{($1#}g;
  ' "$file" >"$tmp"
  mv "$tmp" "$file"
}

rewrite_links() {
  local file="$1"
  local kind="$2" # plugin | crate | guide | root

  local tmp
  tmp="$(mktemp)"

  sed -E \
    -e 's|\(\.\./\.\./pingap-plugin/docs/([a-z0-9_]+)\.md\)|(../plugins/\1)|g' \
    -e 's|\(\.\./pingap-plugin/docs/([a-z0-9_]+)\.md\)|(../plugins/\1)|g' \
    -e 's|\(docs/([a-z0-9_]+)\.md\)|(../plugins/\1)|g' \
    -e 's|\(\.\./\.\./pingap-cache/README\.md\)|(../crates/cache)|g' \
    -e 's|\(\.\./pingap-cache/README\.md\)|(../crates/cache)|g' \
    -e 's|\(\.\./\.\./pingap-plugin/README\.md[^)]*\)|(../plugins/)|g' \
    -e 's|\(\.\./pingap-plugin/README\.md[^)]*\)|(../plugins/)|g' \
    -e 's|\(\.\./pingap-config/README\.md\)|(../crates/config)|g' \
    -e 's|\(\.\./pingap-core/README\.md\)|(../crates/core)|g' \
    -e 's|\(\.\./pingap-upstream/README\.md\)|(../crates/upstream)|g' \
    -e 's|\(\.\./pingap-health/README\.md\)|(../crates/health)|g' \
    -e 's|\(\.\./pingap-discovery/README\.md\)|(../crates/discovery)|g' \
    -e 's|\(\.\./pingap-location/README\.md\)|(../crates/location)|g' \
    -e 's|\(\.\./pingap-certificate/README\.md\)|(../crates/certificate)|g' \
    -e 's|\(\.\./pingap-acme/README\.md\)|(../crates/acme)|g' \
    -e 's|\(\.\./pingap-logger/README\.md\)|(../crates/logger)|g' \
    -e 's|\(\.\./pingap-performance/README\.md\)|(../crates/performance)|g' \
    -e 's|\(\.\./pingap-otel/README\.md\)|(../crates/otel)|g' \
    -e 's|\(\.\./pingap-sentry/README\.md\)|(../crates/sentry)|g' \
    -e 's|\(\.\./pingap-pyroscope/README\.md\)|(../crates/pyroscope)|g' \
    -e 's|\(\.\./pingap-webhook/README\.md\)|(../crates/webhook)|g' \
    -e 's|\(\.\./pingap-proxy/README\.md\)|(../crates/proxy)|g' \
    -e 's|\(\.\./pingap-util/README\.md\)|(../crates/util)|g' \
    -e 's|\(\.\./pingap-imageoptim/README\.md\)|(../crates/imageoptim)|g' \
    -e 's|\(\.\./\.\./pingap-imageoptim/README\.md\)|(../crates/imageoptim)|g' \
    -e 's|\(\.\./docs/README\.md\)|(/guide/modules)|g' \
    -e 's|\(\./docs/README\.md\)|(/guide/modules)|g' \
    -e 's|\(\.\./examples/README\.md\)|(/guide/examples)|g' \
    -e 's|\(\./examples/README\.md\)|(/guide/examples)|g' \
    -e 's|\(\.\./README\.md\)|(/)|g' \
    -e 's|\(\./asset/pingap-logo\.png\)|(/logo.png)|g' \
    -e 's|\(\.\./asset/pingap-logo\.png\)|(/logo.png)|g' \
    -e 's|\(\.\./\.\./asset/pingap-logo\.png\)|(/logo.png)|g' \
    -e 's|\(assets/logo\.png\)|(/logo.png)|g' \
    -e 's|\(\.\./assets/logo\.png\)|(/logo.png)|g' \
    -e 's|src="\.\./\.\./asset/pingap-logo\.png"|src="/logo.png"|g' \
    -e 's|src="\.\./assets/logo\.png"|src="/logo.png"|g' \
    "$file" >"$tmp"

  if [[ "$kind" == "plugin" ]]; then
    sed -E \
      -e 's|\(\.\./\.\./pingap-([a-z0-9-]+)/README\.md\)|(../crates/\1)|g' \
      -e 's|\(\./([a-z0-9_]+)\.md\)|(./\1)|g' \
      "$tmp" >"${tmp}.2" && mv "${tmp}.2" "$tmp"
  fi

  if [[ "$kind" == "crate" ]]; then
    sed -E \
      -e 's|\(\.\./pingap-([a-z0-9-]+)/README\.md\)|(./\1)|g' \
      -e 's|\(\.\./pingap-plugin/docs/([a-z0-9_]+)\.md\)|(../plugins/\1)|g' \
      -e 's|\(\./([a-z0-9_]+)\.md\)|(./\1)|g' \
      "$tmp" >"${tmp}.2" && mv "${tmp}.2" "$tmp"
  fi

  mv "$tmp" "$file"
  strip_md_links "$file"
}

append_source_footer() {
  local file="$1"
  local label="$2"
  local url="$3"
  {
    echo ""
    echo "---"
    echo ""
    echo "*Source: [\`${label}\`](${url})*"
  } >>"$file"
}

# --- clean generated content -------------------------------------------------

clean_generated() {
  # English content at site root (keep VitePress scaffolding)
  rm -rf "${SITE}/plugins" "${SITE}/crates" "${SITE}/guide"
  rm -f "${SITE}/index.md"
  # legacy docsify leftovers
  rm -rf "${SITE}/en"
  rm -f "${SITE}/_sidebar.md" "${SITE}/_navbar.md" "${SITE}/README.md"
}

# --- English assembly (root locale) ------------------------------------------

build_en() {
  echo "Building English content → ${EN} (root locale)"
  mkdir -p "${EN}/crates" "${EN}/plugins" "${EN}/guide"

  for c in "${CRATES[@]}"; do
    local src="${ROOT}/pingap-${c}/README.md"
    local dst="${EN}/crates/${c}.md"
    if [[ ! -f "$src" ]]; then
      echo "  skip missing crate: pingap-${c}" >&2
      continue
    fi
    cp "$src" "$dst"
    rewrite_links "$dst" crate
    append_source_footer "$dst" "pingap-${c}/README.md" \
      "https://github.com/keepmeside/pingap-waf/blob/main/pingap-${c}/README.md"
  done

  cp "${ROOT}/pingap-plugin/README.md" "${EN}/plugins/index.md"
  rewrite_links "${EN}/plugins/index.md" plugin
  sed -E -i.bak \
    -e 's|\[docs/([a-z0-9_]+)\.md\]\(([^)]+)\)|[\1](\2)|g' \
    -e 's|\(docs/([a-z0-9_]+)\.md\)|(./\1)|g' \
    -e 's|\(\.\./plugins/([a-z0-9_]+)\)|(./\1)|g' \
    -e 's|\(\./([a-z0-9_]+)\.md\)|(./\1)|g' \
    "${EN}/plugins/index.md"
  rm -f "${EN}/plugins/index.md.bak"
  strip_md_links "${EN}/plugins/index.md"
  append_source_footer "${EN}/plugins/index.md" "pingap-plugin/README.md" \
    "https://github.com/keepmeside/pingap-waf/blob/main/pingap-plugin/README.md"

  for src in "${ROOT}"/pingap-plugin/docs/*.md; do
    local base
    base="$(basename "$src" .md)"
    local dst="${EN}/plugins/${base}.md"
    cp "$src" "$dst"
    rewrite_links "$dst" plugin
    append_source_footer "$dst" "pingap-plugin/docs/${base}.md" \
      "https://github.com/keepmeside/pingap-waf/blob/main/pingap-plugin/docs/${base}.md"
  done

  cp "${ROOT}/docs/modules.md" "${EN}/guide/modules.md"
  rewrite_links "${EN}/guide/modules.md" guide
  append_source_footer "${EN}/guide/modules.md" "docs/modules.md" \
    "https://github.com/keepmeside/pingap-waf/blob/main/docs/modules.md"

  cp "${ROOT}/docs/acme_chart.md" "${EN}/guide/acme-flow.md"
  rewrite_links "${EN}/guide/acme-flow.md" guide
  append_source_footer "${EN}/guide/acme-flow.md" "docs/acme_chart.md" \
    "https://github.com/keepmeside/pingap-waf/blob/main/docs/acme_chart.md"

  # Fork-owned documentation: the WAF, ACL, bot and control-plane behaviour that
  # upstream does not have, and therefore the pages pingap.io cannot carry. An
  # explicit list rather than a docs/*.md glob, so publishing a page stays a
  # deliberate act that also means adding it to the sidebar in
  # website/.vitepress/config.mts — a glob would silently ship a half-written
  # page with no way to navigate to it.
  local fork_repo="https://github.com/keepmeside/pingap-waf"
  local fork_docs=(
    waf-plugin waf-category-mapping waf-benchmark
    acl-plugin domain-model
    ja4-support
    control-plane-store config-projection
  )
  local page
  for page in "${fork_docs[@]}"; do
    cp "${ROOT}/docs/${page}.md" "${EN}/guide/${page}.md"
    rewrite_links "${EN}/guide/${page}.md" guide
    append_source_footer "${EN}/guide/${page}.md" "docs/${page}.md" \
      "${fork_repo}/blob/main/docs/${page}.md"
  done

  # Spike findings, placed under guide/spikes/ so the `./spikes/<name>.md` links
  # in waf-plugin.md and waf-benchmark.md resolve unchanged. clean_generated
  # removes the whole guide/ tree on every run, so this directory is rebuilt.
  mkdir -p "${EN}/guide/spikes"
  local spike
  for src in "${ROOT}"/docs/spikes/*.md; do
    [[ -f "$src" ]] || continue
    spike="$(basename "$src" .md)"
    cp "$src" "${EN}/guide/spikes/${spike}.md"
    rewrite_links "${EN}/guide/spikes/${spike}.md" guide
    append_source_footer "${EN}/guide/spikes/${spike}.md" \
      "docs/spikes/${spike}.md" "${fork_repo}/blob/main/docs/spikes/${spike}.md"
  done

  cp "${ROOT}/examples/README.md" "${EN}/guide/examples.md"
  rewrite_links "${EN}/guide/examples.md" guide
  sed -E -i.bak \
    -e 's|\(\./([a-z0-9-]+)/README\.md\)|(https://github.com/keepmeside/pingap-waf/tree/main/examples/\1)|g' \
    -e 's|\(\./([a-z0-9-]+)/([a-z0-9.-]+)\)|(https://github.com/keepmeside/pingap-waf/tree/main/examples/\1/\2)|g' \
    "${EN}/guide/examples.md"
  rm -f "${EN}/guide/examples.md.bak"
  strip_md_links "${EN}/guide/examples.md"
  append_source_footer "${EN}/guide/examples.md" "examples/README.md" \
    "https://github.com/keepmeside/pingap-waf/blob/main/examples/README.md"

  cat >"${EN}/crates/index.md" <<'EOF'
# Crates / modules

Each workspace crate has a README describing ownership, configuration and place
in the dependency graph. Content on these pages is copied from the repository
at build time.

| Crate | What it does |
| --- | --- |
| [pingap-util](./util) | Crypto, IP rules, PEM/base64, path and formatting helpers |
| [pingap-core](./core) | `Ctx`, `HttpResponse`, the `Plugin` trait, background services, clock helpers |
| [pingap-config](./config) | Configuration model, storage backends, TOML/HCL/KDL |
| [pingap-discovery](./discovery) | Static / DNS / Docker / transparent backend discovery |
| [pingap-health](./health) | TCP, HTTP(S) and gRPC health checks |
| [pingap-upstream](./upstream) | Load balancing, circuit breaking, upstream connection options |
| [pingap-location](./location) | Host/path matching, rewriting, per-location limits |
| [pingap-certificate](./certificate) | SNI-based dynamic TLS certificate store |
| [pingap-acme](./acme) | Let's Encrypt HTTP-01 and DNS-01 automation |
| [pingap-cache](./cache) | Memory (TinyUFO) and file cache backends |
| [pingap-plugin](./plugin) | Built-in plugins — see the [plugin index](/plugins/) |
| [pingap-imageoptim](./imageoptim) | PNG/JPEG → WebP/AVIF conversion |
| [pingap-logger](./logger) | Access logs, file/syslog writers, rotation and compression |
| [pingap-performance](./performance) | Prometheus metrics and process introspection |
| [pingap-otel](./otel) | OpenTelemetry distributed tracing |
| [pingap-sentry](./sentry) | Sentry error reporting |
| [pingap-pyroscope](./pyroscope) | Continuous CPU profiling |
| [pingap-webhook](./webhook) | Operational notifications to WeCom / DingTalk / HTTP |
| [pingap-proxy](./proxy) | The proxy engine: lifecycle, routing, server configuration |

Also see [Architecture](/guide/modules).
EOF

  # VitePress home
  cat >"${EN}/index.md" <<'EOF'
---
layout: home
hero:
  name: pingap-waf
  text: A native-WAF reverse proxy based on pingap
  tagline: Built on pingap and Cloudflare Pingora — a native Rust WAF with CRS-category parity, per-domain ACL, JA4H bot management and a control plane, on top of upstream's hot reload, web admin and 20+ plugins.
  image:
    src: /logo.png
    alt: pingap-waf
  actions:
    - theme: brand
      text: Get Started
      link: /guide/modules
    - theme: alt
      text: Plugins
      link: /plugins/
features:
  - title: High performance
    details: Built in Rust on Cloudflare Pingora. HTTP/1.1, HTTP/2 and gRPC-Web with low latency and memory safety.
  - title: Hot reload
    details: Apply most config changes without downtime via --autoreload, or graceful restart with --autorestart.
  - title: Plugin gateway
    details: JWT, rate limit, cache, CORS, static files, IP/UA restrictions and more — attach per location.
  - title: Service discovery
    details: Static lists, DNS, Docker labels and transparent proxy modes for dynamic backends.
  - title: Automated HTTPS
    details: Let's Encrypt HTTP-01 and DNS-01 challenges, including wildcards via major DNS providers.
  - title: Observability
    details: Prometheus metrics, OpenTelemetry traces, structured access logs, Sentry and Pyroscope.
---

## Quick start

### Docker Compose

```yaml
services:
  pingap:
    image: vicanso/pingap:latest
    container_name: pingap-instance
    restart: always
    ports:
      - "80:80"
      - "443:443"
    volumes:
      - ./pingap_data:/opt/pingap
    environment:
      - PINGAP_CONF=/opt/pingap/conf
      - PINGAP_ADMIN_ADDR=0.0.0.0:80/pingap
      - PINGAP_ADMIN_USER=pingap
      - PINGAP_ADMIN_PASSWORD=<YourSecurePassword>
    command: ["pingap", "--autoreload"]
```

```bash
mkdir pingap_data
docker compose up -d
# Admin UI: http://localhost/pingap
```

### Install binary

```bash
curl -sSL https://raw.githubusercontent.com/vicanso/pingap/main/install.sh | sh
# Full build: PINGAP_FULL=1 sh
```

### One-command HTTPS proxy

```bash
pingap-waf --domain=pingap.io --upstream=192.168.1.1:3000
```

## Browse the docs

| Section | Description |
| --- | --- |
| [Architecture](/guide/modules) | Crate dependency graph and module roles |
| [Plugins](/plugins/) | Full plugin index and configuration |
| [Crates](/crates/) | Workspace crate reference |
| [Examples](/guide/examples) | API gateway, gRPC-Web, static serve, and more |
| [ACME flow](/guide/acme-flow) | Certificate issuance sequence diagrams |

## Configuration sketch

```toml
[servers.main]
addr = "0.0.0.0:6188"
locations = ["api"]

[locations.api]
upstream = "api"
path = "/api"
plugins = ["compression", "jwtAuth"]

[upstreams.api]
addrs = ["10.0.0.1:8080", "10.0.0.2:8080"]
discovery = "dns"
update_frequency = "30s"

[plugins.jwtAuth]
category = "jwt"
header = "Authorization"
secret = "change-me"
algorithm = "HS256"

[plugins.compression]
category = "compression"
gzip_level = 6
br_level = 6
zstd_level = 3
```

Supports **TOML**, **HCL** and **KDL**. Details in [pingap-config](/crates/config).

## Request lifecycle

| Step | When | Typical use |
| --- | --- | --- |
| `early_request` | After headers, before routing | Accept-Encoding, compression negotiate |
| `request` | After location match | Auth, limit, cache, static files |
| `proxy_upstream` | Before backend selection | Checks that skip cache hits |
| `upstream_response` | Upstream response headers | Header rewrite, body transform |
| `response` | Before sending to client | Response headers, sub_filter |

See [pingap-proxy](/crates/proxy) and [Plugin lifecycle](/plugins/#lifecycle-steps).
EOF
}

# --- main --------------------------------------------------------------------

mkdir -p "${SITE}/public" "${SITE}/.vitepress/theme"
if [[ ! -f "${SITE}/public/logo.png" ]]; then
  cp "${ROOT}/asset/pingap-logo.png" "${SITE}/public/logo.png" 2>/dev/null \
    || cp "${ROOT}/icons/pingap-256.png" "${SITE}/public/logo.png"
fi

clean_generated
build_en

echo ""
echo "VitePress content assembled under ${SITE}"
echo "  EN  plugins=$(find "${EN}/plugins" -name '*.md' | wc -l | tr -d ' ') crates=$(find "${EN}/crates" -name '*.md' | wc -l | tr -d ' ') guide=$(find "${EN}/guide" -name '*.md' | wc -l | tr -d ' ')"
echo ""
echo "Next:"
echo "  cd website && npm install && npm run docs:dev"
echo "  # or production build:"
echo "  cd website && npm run docs:build   # output → website/.vitepress/dist"
