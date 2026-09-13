# Building the documentation site

Documentation for pingap-waf, built with **[VitePress](https://vitepress.dev/)**.
English only.

Nothing builds or deploys this automatically: the fork does not vendor upstream's
`.github/workflows/pages.yml` (see the root `NOTICE` for why), so both the assembly
step and the VitePress build are run by hand. Upstream's <https://pingap.io/> is
built from upstream's tree and does not carry any page from this repository.

## Layout

| Path | Role |
| --- | --- |
| `.vitepress/config.mts` | VitePress config — nav, sidebar, mermaid, `base` |
| `.vitepress/theme/` | Brand colours and layout tweaks |
| `public/logo.png` | Site logo |
| `index.md`, `plugins/`, `crates/`, `guide/` | **Generated** content |
| `package.json`, `package-lock.json` | VitePress + mermaid deps |

Do **not** edit generated markdown under `plugins/`, `crates/` or `guide/` by hand —
re-run the build script. Hand-maintained files are `BUILD.md`, `.vitepress/config.mts`,
`.vitepress/theme/`, `package.json`, `package-lock.json` and `public/`.

## Local development

```bash
# 1. Assemble markdown from the monorepo
./scripts/build-website.sh

# 2. Install deps (once) and start the VitePress dev server
cd website
npm install
npm run docs:dev
# open the printed local URL (usually http://127.0.0.1:5173/)
```

Production build:

```bash
./scripts/build-website.sh
cd website
npm run docs:build
# output: website/.vitepress/dist
npm run docs:preview
```

If you deploy under a subpath (e.g. `username.github.io/pingap/` without a
custom domain):

```bash
DOCS_BASE=/pingap/ npm run docs:build
```

`DOCS_BASE` is read by `.vitepress/config.mts` and defaults to `/`.

## What the site is assembled from

`scripts/build-website.sh` is the authoritative mapping. It copies:

| Site path | Source |
| --- | --- |
| `crates/*` | `pingap-*/README.md` (one page per crate) |
| `plugins/index.md` | `pingap-plugin/README.md` |
| `plugins/*` | `pingap-plugin/docs/*.md` |
| `guide/modules.md` | `docs/modules.md` |
| `guide/acme-flow.md` | `docs/acme_chart.md` |
| `guide/examples.md` | `examples/README.md` |
| `index.md` | generated inline by the script |

**The fork's own pages are not part of the site.** `docs/waf-plugin.md`,
`docs/acl-plugin.md`, `docs/ja4-support.md`, `docs/control-plane-store.md`,
`docs/config-projection.md`, `docs/domain-model.md`, `docs/waf-benchmark.md` and
`docs/waf-category-mapping.md` are not copied by the script, so they are read on
GitHub rather than on the site. Adding them means extending `build_en` and the
`guide` sidebar in `.vitepress/config.mts`.

Generated and gitignored — never edit by hand: `index.md`, `plugins/`, `crates/`,
`guide/`.
