# Prior art

No usable standard for describing service fingerprints exists. The closest attempt, [Pythia](https://github.com/EfstratiosLontzetidis/pythia) (2024), is Sigma-inspired but stopped at 8 commits and converts queries by plain string substitution.

Each existing format covers part of the problem. None combines an engine-neutral field taxonomy, Sigma-style boolean logic, engine-query conversion and active confirmation.

| Format | Shape | What it matches | Converts to engine queries | Active probing | Status and lesson |
| --- | --- | --- | --- | --- | --- |
| [Nmap service probes](https://nmap.org/book/vscan-fileformat.html) | Flat-file DSL: `Probe` + `match`/`softmatch` | PCRE on TCP/UDP responses, with version templates | No | Yes | Mature, but Nmap-only. The [Nmap licence](https://svn.nmap.org/nmap-releases/nmap-7.30/service_scan.h) covers software that reads `nmap-service-probes`. Lesson: probe library + soft matches. |
| [Rapid7 Recog](https://github.com/rapid7/recog) | XML | One regex per pre-extracted field (SSH banner, HTTP Server, favicon, JARM) | No | No, needs pre-processing | Maintained, used by Metasploit and InsightVM. Lesson: `param` extraction and examples that double as tests. |
| [Wappalyzer forks](https://github.com/enthec/webappanalyzer) | JSON | Web tech: HTML, headers, cookies, scripts, `implies` | No | Passive web | Upstream went closed in 2023; GPL-3.0 forks continue. Lesson: technology implication chains. |
| [Nuclei templates](https://projectdiscovery.io/blog/ultimate-nuclei-guide) | YAML | Request + matchers per protocol (word, regex, favicon, DSL) | No, only a `shodan-query` metadata string | Yes | Huge library, but vulnerability-oriented; matcher logic is per request, not across fields. |
| [FingerprintHub](https://github.com/0x727/fingerprinthub) | YAML, Nuclei-inspired | HTTP/TCP probes, matchers, extractors, CPE | No | Yes | Active, web-focused, feeds observer_ward. Closest on the scanning side. |
| [fingerprintx / Nerva](https://www.praetorian.com/blog/whats-running-on-that-port-introducing-nerva-for-service-fingerprinting/) | Go code plugins | 170+ protocols across TCP, UDP, SCTP | No | Yes | Apache 2.0, but fingerprints are code, not shareable data. |
| [awesome-search-queries](https://github.com/projectdiscovery/awesome-search-queries) | YAML list | Hand-written query strings per engine and product | Not needed: one string per engine | No | Used by uncover `-asq`. Shows the demand, but every engine query is written by hand. |
| [Pythia](https://github.com/EfstratiosLontzetidis/pythia) | YAML, Sigma-inspired | `field:value` parts + condition | Yes: Shodan, Censys, FOFA, BinaryEdge, ZoomEye, Hunter | No | 8 commits, 34 stars, created August 2024. Converts by 1:1 string replacement, which the README warns can produce wrong queries. |
| [JARM](https://github.com/salesforce/jarm), [JA4+](https://github.com/FoxIO-LLC/ja4) | Hash methods | TLS/TCP/HTTP behaviour | n/a | Yes | Inputs, not rule formats. JA4S, JA4X and JA4T are under the FoxIO License 1.1, which is not permissive for monetisation. |

## What Athar takes from each

Pythia is closest on conversion, FingerprintHub on scanning, and Recog on identity output. Athar takes:

- **Sigma:** metadata, selections, modifiers and conditions.
- **Recog:** value extraction (`param` → `extract`) and examples that run as tests.
- **Nmap:** a shared probe library and the hard-match/soft-match idea (variant over family, higher confidence wins).
- **Wappalyzer:** the idea of relations between fingerprints (`related`, `variant-of`).

And adds what none of them has: conversion to engine queries with declared fidelity, checked by the same evaluator that confirms live hits. The same rules also convert to Nuclei templates, so they run in a scanner many hunters already use.

## Why now

Every hunt gets re-published as three or four engine-specific queries (see the ARTEX posts by Gameel Ali). Engines change their syntax under you: [Censys deprecated Legacy Search in September 2026](https://censys.com/blog/legacy-search-deprecation/). Nmap's probe database is tied to Nmap's licence, and [Wappalyzer went closed-source in 2023](https://github.com/enthec/webappanalyzer).
