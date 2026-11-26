# Design decisions

This file tracks what is decided, what is open, and what is deliberately deferred. A new idea starts as an issue. It goes into the spec only when real rules need it; until then it waits under [Deferred](#deferred) with a note on what would make us revisit it.

## Decided

### Name: Athar

Athar (أثر) is Arabic for *trace* or *footprint*: the mark something leaves behind. The working title of the draft was "Service Fingerprint Rules".

### Own standard, Sigma-compatible detection

Athar is its own specification. Its `detection` block is valid Sigma; `target`, `probes`, `identifies`, `extract` and `tests` sit on top.

The alternative was plain Sigma rules with `logsource: { product: internet-scan, service: http }` and pySigma backends for FOFA, Shodan and Censys. We rejected it because Sigma's semantics are built around log events, and active probing, identity output and conversion fidelity would have to be bent around them. Reusing only the grammar keeps the format familiar to Sigma authors without that cost.

### One rule matches one service

The unit of matching is one service: one IP address and one port. All selections of a rule hold on the same service, and every identity record describes one service. This keeps the evaluator, the scanner output, the tests and the engine conversion simple. Combinations across ports are [deferred](#multi-service-fingerprints).

### No `level` field

Sigma's `level` says how urgent an alert is. For a service fingerprint the answer depends on who is looking: a C2 panel is urgent for a defender and routine for the red team that runs it. A rule already states what the service is (`identifies.category`) and how sure the match is (`confidence`), and each consumer maps those to its own priority. `level` was in the first draft and was removed on 2026-11-25; `athar verify` now reports it as an unknown key.

### No hit counts in rules

The first draft had a `validation` section for search-engine hit counts (engine, date, results). No tool read it, and the numbers went out of date soon after the rule was written. Hit counts go into the pull request description instead, and `references` points to the published hunt. Removed on 2026-11-25.

### urlscan.io as a convert target

urlscan.io is not a port scanner. It records what a browser showed for URLs that people or feeds submitted, after redirects, and indexes the page's title, Server header, status, TLS issuer and response hashes. It still earns a backend: it reaches pages behind hostnames that IP-based crawlers never request, such as the `sslip.io` names in the ARTEX results, and the ARTEX family query found 1,111 scans there (25 November 2026, last 365 days). Most rules convert to a superset there, and the notes say so.

### Nuclei templates as a convert target

Many hunters already run Nuclei, so `athar convert -t nuclei` writes one template per rule (decided 2026-11-25). A scanner sees the whole live response, so most rules convert exactly, unlike engine queries. The rule's condition becomes one DSL matcher, which keeps negations and nested conditions; the template rebuilds the fields Athar's scanner reads. Templates are tested against real Nuclei with each rule's own tests. Other scanners and formats wait in [conversion-targets.md](conversion-targets.md) until someone asks for them, because every backend has to be maintained.

### Nmap NSE as a convert target

Nmap has the widest reach of any scanner, so `athar convert -t nse` came next (decided 2026-11-25). Every rule converting to generated Lua code would be much code to review, so the conversion is data instead: one hand-written script, `athar.nse`, embedded in the CLI, and one data file per rule with the condition (after the superset rule), folded literals, custom probes and what the rule needs from the baseline probe. The script is a second scanner and follows `athar scan` closely: it sends its own requests over Nmap's sockets rather than through `http.lua`, and reads status lines, headers, chunked and gzip bodies, titles, favicons and certificates as Go's libraries do. NSE has no PCRE binding, so regular expressions are compiled by Go's `regexp/syntax` and run in the script on a small Pike VM, which finds the same matches and groups as Go. Custom probes need `--script-args athar.probes`, like `athar scan -probes`. A test runs `athar scan` and the script on the same raw responses and compares every field. `athar.nse` carries an MIT header; the rule data keeps each rule's licence.

### CLI in Go

The reference CLI is written in Go. Rust and Python were the alternatives.

- **Scanning is network-bound.** Throughput depends on concurrency, timeouts and rate limits, not on raw CPU speed. Goroutines handle tens of thousands of open connections, and the CPU work per response (regex, mmh3, SHA-256, JARM) is cheap in any compiled language. Rust's speed advantage would rarely show.
- **RE2 out of the box.** The spec requires RE2 regex syntax. Go's standard `regexp` package implements RE2, so the reference implementation matches the spec without a third-party engine.
- **The scanning ecosystem is Go.** httpx, naabu, nuclei, zgrab2 and fingerprintx are Go, and ProjectDiscovery's uncover already queries FOFA, Shodan, Censys and ZoomEye. Their libraries can be reused or studied, and their users can contribute.
- **One static binary.** It cross-compiles to every platform with no runtime to install.
- **Reviewable.** The maintainers write Go, so AI-assisted code can be reviewed by the people responsible for the standard. A reference implementation nobody on the team can review is a liability.
- **Conversion stays easy.** Converting a rule is string building over a small syntax tree, which is no harder in Go than in Python.

What we give up is pySigma's parser and condition engine. The condition grammar is small (named selections, `and`, `or`, `not`, parentheses, `1 of`, `all of`), so owning it in Go is a few hundred lines, and existing Go Sigma parsers such as [sigma-go](https://github.com/bradleyjkemp/sigma-go) can serve as a reference. Because the `detection` block is valid Sigma, a thin pySigma backend can still be added later for people who work in sigma-cli.

Rust would be worth revisiting only if evaluation became CPU-bound, for example matching thousands of rules against millions of stored responses. The evaluator could then be replaced on its own.

### One version, released from tags

A single tag such as `v0.1.0` versions the spec, the rules and the CLI together, which is why `go.mod` sits at the repository root. The spec carries no version number of its own. Pushing the tag builds the binaries and publishes the GitHub release. Separate versions per part can come later if the parts start moving at different speeds.

### Rules under the Detection Rule License 1.1

Every rule in this repository is licensed under the [Detection Rule License (DRL) 1.1](../LICENSE.Detection.Rules.md), decided on 2026-11-25. It is the licence of the Sigma rules, so people who already use Sigma know its terms. It allows any use, commercial included, and asks for one thing in return: credit. Whoever shares a rule keeps its `author`, a link and the licence, and messages based on a rule's matches name its author. Rules already carry an `author` field, so nothing in the format changes.

### Baseline follows redirects on the same service

Decided on 2026-11-26, not built yet. Today the baseline probe follows no redirect, so a service that redirects from `/` shows only the redirect. Two cases made the decision: RedAmon answers `GET /` with a redirect to `/login`, and 1 of 15 live ARTEX hosts (2026-11-26) served a page with a meta refresh to `/function/tasks/` in place of the console. The baseline will follow a few redirects that stay on the same service and match the page they lead to. Still to settle when it is built: how many redirects, whether a meta refresh counts as one, and how conversions are labelled, since engines differ (urlscan.io follows redirects; for the others it is unknown). Until then a rule matches the redirect itself (`http.headers.location`, or the refresh target in the body) or another signal such as the favicon.

## Open

- **Baseline probe.** How each engine actually fetches (redirects, Host header and SNI, favicon source, body truncation) is unknown. A controlled server that logs every request from FOFA, Shodan, Censys, ZoomEye and Modat crawlers would settle it.
- **Undocumented hashes.** FOFA `body_hash` and `header_hash`, ZoomEye `http.body_hash` and Modat `http.body_mmh3` need their algorithms identified before they can map to taxonomy fields.
- **Body size limit.** `http.body` holds the first 1 MiB for now; the limit still has to be agreed.
- **Variant inheritance.** Variants repeat their family's selections today. An `extends: <id>` key would remove the duplication, but every converter would need to resolve it.
- **Licensing.** Rules are under DRL 1.1 (decided above). The licence for the CLI, the spec and the docs is still to be chosen. JA4+ fields stay optional because of the FoxIO licence, and [JARM and HASSH are reportedly patented](https://hdm.io/posts/20230927111137909613461915/), which needs checking. Nothing may be copied from `nmap-service-probes`.
- **Active probing policy.** Scanning infrastructure you don't own carries legal and ethical limits. Proposal: baseline probe only by default, custom probes opt-in, safe methods only, rate limits in the reference scanner.
- **Format versioning.** A top-level `format: 1` key would let converters reject rules written for a newer spec.

## Deferred

### Multi-service fingerprints

**The idea.** Some services might only be identifiable through a combination of ports on one host. Picture a framework whose operator UI on 443 looks like a generic nginx page and whose agent API on 8443 presents a default certificate that other products share too. Neither port is specific on its own; together they would be.

**Why it is not in the spec yet.**

- **No known case needs it.** The strong signals (default certificates, favicons, titles, banners, JARM) sit on a single service. Where a framework exposes several ports, each one is usually identifiable alone, and the second port only adds confidence.
- **It changes the unit of everything.** The evaluator, the identity record (`ip:port` becomes `ip`), the tests and the scanner would all have to work per host. The scanner would also have to probe ports it was not asked about.
- **Engines can't express it.** FOFA, Shodan and ZoomEye match one service record at a time. Censys and Modat can match across the services of a host (Modat with several `same_service()` groups), but no other engine can. On the other engines a two-port rule would convert to a superset of one port at best.
- **Passive data is weak for it.** Engines crawl ports at different times, so two records on one IP may never have been live at the same moment.

**If it becomes necessary**, it should be a separate rule type that refers to service rules, not a change to service rules. Sigma did the same with correlation rules: they arrived later as their own type that references base rules by id or name, and existing rules stayed untouched. An Athar host rule would look roughly like this (hypothetical, not part of the spec):

```yaml
title: ExampleFramework, operator UI and agent API on one host
id: <uuid>
correlation:
  type: same_host
  rules:
    - <id of the UI service rule>
    - <id of the agent API service rule>
identifies:
  product: ExampleFramework
  category: offensive-tool
confidence: high
```

Consumers that don't support host rules would ignore them. The scanner would get them almost for free: it already emits one identity record per service, and a host rule is a group-by on IP over those records. Until then, hunters can group `athar scan` output by IP themselves.

**Revisit when** we have at least three real services where no single-port rule reaches `medium` confidence but a combination reaches `high`. Collect candidates in issues labelled `multi-service`.

## Next steps

- [x] Decide standalone vs Sigma extension, pick a name, create the repository
- [ ] Freeze the field taxonomy and write a JSON Schema
- [ ] Run the baseline-probe measurement against FOFA, Shodan, Censys, ZoomEye and Modat
- [x] Build the evaluator and `athar verify`, and run it in CI
- [x] Build `athar scan` for TCP, TLS and HTTP on hosts, CIDR ranges and ports
- [ ] Add JARM, JA3S and SSH host key fields to `athar scan`
- [x] Build `athar convert` for FOFA, Shodan, Censys, ZoomEye, Modat and urlscan.io
- [x] Convert rules to Nuclei templates
- [x] Convert rules to an Nmap script (NSE)
- [ ] Seed 20–30 rules with tests from published hunts (ARTEX family, common C2 panels)
