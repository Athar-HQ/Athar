# Rules

Each file is one Athar rule describing one network service. The format is defined in [spec/athar-spec.md](../spec/athar-spec.md). To turn a search-engine query into a rule, or to let an AI agent do it, see [AGENTS.md](../AGENTS.md).

## Layout

One folder per category, using the controlled category list from the spec:

```text
rules/
├── c2/
├── offensive-tool/
│   ├── aof_artex_nov26.yml                  family rule
│   ├── aof_artex_antifox_nov26.yml          AntiFox variant
│   ├── aof_artex_artex_nov26.yml            ARTEX variant
│   ├── aof_artex_artex_favicon_nov26.yml    ARTEX favicon
│   ├── aof_artex_basic_auth_nov26.yml       ARTEX behind Basic auth
│   ├── aof_artex_frontend_files_nov26.yml   SHA-256 of the family's frontend stylesheets
│   ├── aof_artex_llm_console_nov26.yml      LLM-driven console phrase
│   ├── aof_artex_rebrands_nov26.yml         family without ARTEX's title or favicon
│   └── aof_artex_stylesheet_nov26.yml       paths of the family's frontend stylesheets
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

Test responses may be minimal samples built from published indicators while a rule is `experimental`. Say so in a comment. Captured responses are better.

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
