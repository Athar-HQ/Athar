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

A single tag such as `v0.1.0` versions the spec, the rules and the CLI together, which is why `go.mod` sits at the repository root. Pushing the tag builds the binaries and publishes the GitHub release. Separate versions per part can come later if the parts start moving at different speeds.

## Open

- **Baseline probe.** How each engine actually fetches (redirects, Host header and SNI, favicon source, body truncation) is unknown. A controlled server that logs every request from FOFA, Shodan, Censys and ZoomEye crawlers would settle it.
- **Undocumented hashes.** FOFA `body_hash` and `header_hash`, and ZoomEye `http.body_hash`, need their algorithms identified before they can map to taxonomy fields.
- **Body size limit.** `http.body` holds the first 1 MiB for now; the limit still has to be agreed.
- **Tests for custom probes.** `tests.response` covers the baseline probe only. Rules with custom probes need a way to give one response per probe.
- **Variant inheritance.** Variants repeat their family's selections today. An `extends: <id>` key would remove the duplication, but every converter would need to resolve it.
- **Licensing.** Rules under DRL 1.1, as Sigma. Licence for the CLI to be chosen. JA4+ fields stay optional because of the FoxIO licence, and [JARM and HASSH are reportedly patented](https://hdm.io/posts/20230927111137909613461915/), which needs checking. Nothing may be copied from `nmap-service-probes`.
- **Active probing policy.** Scanning infrastructure you don't own carries legal and ethical limits. Proposal: baseline probe only by default, custom probes opt-in, safe methods only, rate limits in the reference scanner.
- **Format versioning.** A top-level `format: 1` key would let converters reject rules written for a newer spec.

## Deferred

### Multi-service fingerprints

**The idea.** Some services might only be identifiable through a combination of ports on one host. Picture a framework whose operator UI on 443 looks like a generic nginx page and whose agent API on 8443 presents a default certificate that other products share too. Neither port is specific on its own; together they would be.

**Why it is not in v0.1.**

- **No known case needs it.** The strong signals (default certificates, favicons, titles, banners, JARM) sit on a single service. Where a framework exposes several ports, each one is usually identifiable alone, and the second port only adds confidence.
- **It changes the unit of everything.** The evaluator, the identity record (`ip:port` becomes `ip`), the tests and the scanner would all have to work per host. The scanner would also have to probe ports it was not asked about.
- **Engines can't express it.** FOFA, Shodan and ZoomEye match one service record at a time. Censys can match across the services of a host, but only Censys. On the other engines a two-port rule would convert to a superset of one port at best.
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
- [ ] Freeze the v0.1 field taxonomy and write a JSON Schema
- [ ] Run the baseline-probe measurement against FOFA, Shodan, Censys and ZoomEye
- [x] Build the evaluator and `athar verify`, and run it in CI
- [ ] Build `athar convert` for FOFA, Shodan and Censys
- [ ] Build `athar scan` for HTTP and TLS
- [ ] Seed 20–30 rules with tests from published hunts (ARTEX family, common C2 panels)
