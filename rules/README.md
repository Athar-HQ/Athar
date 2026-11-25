# Rules

Each file is one Athar rule describing one network service. The format is defined in [spec/athar-spec.md](../spec/athar-spec.md).

## Layout

One folder per category, using the controlled category list from the spec:

```text
rules/
├── c2/
├── offensive-tool/
│   ├── ai_autonomous_pentest_console.yml         family rule
│   └── ai_autonomous_pentest_console_artex.yml   variant rule
├── phishing-kit/
└── …
```

Create a category folder when its first rule arrives.

## File names

- Lowercase, words separated by underscores, extension `.yml`.
- Name the file after the product or family it identifies: `ai_autonomous_pentest_console.yml`.
- A variant adds its name to the family's file name: `ai_autonomous_pentest_console_artex.yml`. Family and variants then sort next to each other.

## Checklist before a pull request

- [ ] `id` is a fresh UUIDv4. Published ids never change.
- [ ] `status: experimental` for new rules.
- [ ] `references` point to the public source of the hunt.
- [ ] At least one `match` test and one `no_match` test. The negative test should be a near miss (similar title, generic page), not random text.
- [ ] No engine syntax outside `native`. Detection uses taxonomy fields only.
- [ ] Baseline probe only, unless the service can't be identified without a custom probe. Custom probes use GET, HEAD or OPTIONS, no credentials, no payloads.
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
    expect: match
    response:
      http.title: '<title>'
      http.body: '... <string> ...'
  - name: <near miss>
    expect: no_match
    response:
      http.title: '<similar but different title>'
      http.body: '...'
native:
  <engine>: '<the query you originally used>'
```
