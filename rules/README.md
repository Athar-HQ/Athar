# Rules

Each file is one Athar rule describing one network service. The format is defined in [spec/athar-spec.md](../spec/athar-spec.md). To turn a search-engine query into a rule, or to let an AI agent do it, see [AGENTS.md](../AGENTS.md).

## Layout

One folder per category, using the controlled category list from the spec:

```text
rules/
├── c2/
├── offensive-tool/
│   ├── aof_artex_nov26.yml                         family rule
│   ├── aof_artex_antifox_nov26.yml                 AntiFox variant
│   ├── aof_artex_artex_nov26.yml                   ARTEX variant
│   ├── aof_artex_artex_favicon_nov26.yml           ARTEX favicon
│   ├── aof_artex_basic_auth_nov26.yml              ARTEX behind Basic auth
│   ├── aof_artex_frontend_files_nov26.yml          SHA-256 of the family's frontend stylesheets
│   ├── aof_artex_llm_console_nov26.yml             LLM-driven console phrase
│   ├── aof_artex_opx_nov26.yml                     OPX rebrand with an operations console title
│   ├── aof_artex_rebrands_nov26.yml                family without ARTEX's title or favicon
│   ├── aof_artex_redirect_stub_nov26.yml           ARTEX page that redirects to the console
│   ├── aof_artex_scopeweaver_nov26.yml             ScopeWeaver variant
│   ├── aof_artex_stylesheet_nov26.yml              paths of the family's frontend stylesheets
│   ├── aof_autocve_nov26.yml                       AutoCVE title
│   ├── aof_autocve_favicon_nov26.yml               favicon, MurmurHash3
│   ├── aof_autocve_favicon_sha256_nov26.yml        favicon, SHA-256
│   ├── aof_cairn_nov26.yml                         console title of the Cairn fork CL-STA-1238 used
│   ├── aof_cairn_cert_nov26.yml                    the fork's certificate, common name
│   ├── aof_cairn_cert_org_nov26.yml                the fork's certificate, organisation
│   ├── aof_cyberstrikeai_nov26.yml                 CyberStrikeAI title
│   ├── aof_cyberstrikeai_cert_nov26.yml            default certificate
│   ├── aof_cyberstrikeai_favicon_nov26.yml         favicon, MurmurHash3
│   ├── aof_cyberstrikeai_favicon_sha256_nov26.yml  favicon, SHA-256
│   ├── aof_cyberstrikeai_wordmark_nov26.yml        wordmark in the classic interface
│   ├── aof_deepaudit_nov26.yml                     DeepAudit title
│   ├── aof_deepaudit_favicon_nov26.yml             favicon, MurmurHash3
│   ├── aof_deepaudit_favicon_sha256_nov26.yml      favicon, SHA-256
│   ├── aof_luan1aoagent_nov26.yml                  LuaN1aoAgent workbench title
│   ├── aof_pentagi_cert_nov26.yml                  default certificate, issuer
│   ├── aof_pentagi_cert_san_nov26.yml              default certificate, DNS name
│   ├── aof_pentagi_favicon_nov26.yml               favicons, MurmurHash3
│   ├── aof_pentagi_favicon_sha256_nov26.yml        favicons, SHA-256
│   ├── aof_pentestcode_nov26.yml                   PentestCode web interface title
│   ├── aof_redamon_nov26.yml                       RedAmon title
│   ├── aof_redamon_favicon_nov26.yml               favicons, MurmurHash3
│   ├── aof_redamon_favicon_sha256_nov26.yml        favicons, SHA-256
│   ├── aof_strix_nov26.yml                         Strix results viewer title
│   ├── aof_strix_favicon_nov26.yml                 viewer icon, MurmurHash3
│   ├── aof_strix_favicon_sha256_nov26.yml          viewer icon, SHA-256
│   ├── aof_strix_server_nov26.yml                  viewer Server header
│   └── aof_xalgorix_nov26.yml                      Xalgorix dashboard title
├── phishing-kit/
└── …
```

Create a category folder when its first rule arrives.

## File names

- Lowercase, words separated by underscores, extension `.yml`.
- Name the file after the product or family it identifies: `aof_artex_nov26.yml` for the ARTEX family of agentic offensive frameworks (AOF).
- A variant adds its name to the family's file name: `aof_artex_artex_nov26.yml` for its ARTEX brand. Family and variants then sort next to each other.
- End the name with the month and year of the rule's `date`, as `_<mon><yy>`: `_nov26` for a rule first written in November 2026. The suffix stays when the rule is modified later, so a file name always tells when the rule was written.

## Checklist before a pull request

- [ ] `id` is a fresh UUIDv4. Published ids never change.
- [ ] `status: experimental` for new rules.
- [ ] `author` credits you the way you want: rules are licensed under the [DRL 1.1](../LICENSE.Detection.Rules.md), which requires everyone who shares the rule or reports its matches to keep it.
- [ ] `references` point to the public source of the hunt.
- [ ] At least one `match` test and one `no_match` test. The negative test should be a near miss (similar title, generic page), not random text.
- [ ] No engine syntax outside `native`. Detection uses taxonomy fields only.
- [ ] Baseline probe only, unless the service can't be identified without a custom probe or the rule checks the hash of a file the page loads. Custom probes use GET, HEAD or OPTIONS, no credentials, no payloads, and tests give their responses under `probes`.
- [ ] `confidence` reflects how likely a match is really this service and not something that looks like it.
- [ ] If you ran the query on a search engine, the engine, date and hit count are in the pull request description, not in the rule.
- [ ] Variants link to their family with `related` type `variant-of` and repeat the family's selections.
- [ ] `athar verify -strict rules/` passes. CI runs the same check on every pull request.

Test responses may be minimal samples built from published indicators while a rule is `experimental`. Say so in a comment. A captured response is better: put it under `raw` as received, and `athar verify` derives the fields from it as the scanner does (spec section 9).

## Template

```yaml
title: <Product or family name>
id: <uuidv4>
status: experimental
description: |
  <What the service is and why the fingerprint works.>
references:
  - <public source of the hunt>
author: <Name (@handle)>
date: <YYYY-MM-DD>
tags:
  - category.<category>
target:
  protocol: http
  tls: auto
detection:
  selection_title:
    http.title|contains: '<distinctive title>'
  selection_body:
    http.body|contains: '<distinctive string in the landing page>'
  condition: selection_title and selection_body
identifies:
  product: <Product>
  family: <family-slug>
  category: <category>
confidence: medium
falsepositives:
  - <when a legitimate service would match>
tests:
  - name: <positive case>
    response:
      http.title: '<title>'
      http.body: '... <string> ...'
    expect: match
  - name: <near miss>
    response:
      http.title: '<similar but different title>'
      http.body: '...'
    expect: no_match
native:
  <engine>: '<the query you originally used>'
```
