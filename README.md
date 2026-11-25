<p align="center">
  <img src="docs/images/athar-banner.png" alt="Athar — Service Fingerprinting. Rule Standard, Query Converter, Scanner." width="900">
</p>

# Athar

**Athar** is a service fingerprinting project built around a draft standard for portable YAML rules. Each rule describes one network service using observable signals such as HTTP headers, TLS certificates, or response banners.

- **Rule standard.** Define service fingerprints in YAML with Sigma-style detection logic and test cases.
- **Query converter.** Translate the same rules into queries for FOFA, Shodan, Censys, and ZoomEye to find candidate services in indexed scan data.
- **Scanner.** Apply those rules to live services on specified hosts or network ranges to identify products, families, and versions.

> **Status (draft v0.1).** The Go CLI supports `athar scan` for live scanning and `athar verify` for syntax checks and rule tests. Query conversion and matching against stored data are planned.

The first use case is the infrastructure of **agentic offensive frameworks (AOFs)**: AI-driven penetration testing consoles that are deployed under changing brand names. The format is not limited to them; C2 panels, phishing kits, appliances and ordinary server software fit the same way.

## Why

Every infrastructure hunt gets published three or four times, once per search engine, as hand-written query strings. Those strings drift apart, break when an engine changes its syntax (Censys [deprecated Legacy Search](https://censys.com/blog/legacy-search-deprecation/) in September 2026), and can't be tested.

Existing fingerprint formats each cover part of the problem. Nmap's probe database is tied to Nmap's licence, Recog produces no queries, Nuclei templates are built for vulnerabilities, and Wappalyzer went closed-source. None of them combines an engine-neutral field set, Sigma-style logic, query conversion and active confirmation. [docs/prior-art.md](docs/prior-art.md) compares them.

## A rule

If you can read a Sigma rule, you can read this one. The metadata and the `detection` block are Sigma. New are `target`, `identifies`, `extract`, `confidence` and `tests`.

```yaml
title: Agentic Offensive Framework - ARTEX family
id: 0ce69e91-baee-4475-81ee-4b8eca1a6c3b
status: experimental
author: Gameel Ali (@MalGamy12)
date: 2026-11-24
target:
  protocol: http
  tls: auto
detection:
  selection_title:
    http.title|contains: 'Autonomous Penetration Testing Console'
  selection_route:
    http.body|contains: '/function/tasks'
  condition: selection_title and selection_route
identifies:
  family: artex
  category: offensive-tool
extract:
  brand:
    field: http.title
    regex: '^(?P<brand>.+?)\s+[—–-]\s+Autonomous Penetration Testing Console'
confidence: high
tests:
  - name: NKW branding
    expect: match
    extracted: { brand: NKW }
    response:
      http.title: 'NKW — Autonomous Penetration Testing Console'
      http.body: '... /function/tasks ...'
```

The full rule, with its description, negative test and the original FOFA query, is in [rules/offensive-tool/aof_artex.yml](rules/offensive-tool/aof_artex.yml).

## How it works

The rules are the only thing the commands share. Each command takes the rules plus its own input, and none of them needs another command to run first.

```mermaid
flowchart LR
  R["Rules<br/>(YAML)"]
  T["Hosts, CIDR ranges<br/>and ports"]
  D["Stored data<br/>engine exports,<br/>recorded responses"]

  R --> S(["athar scan"])
  T --> S
  S --> SO["Matched services<br/>live"]

  R --> C(["athar convert"])
  C --> CO["Search-engine queries<br/>FOFA · Shodan · Censys · ZoomEye"]

  R --> M(["athar match"])
  D --> M
  M --> MO["Matched records<br/>no packets sent"]
```

- **`athar scan`** checks live services. Give it rules, hosts or CIDR ranges, and the ports to check (`-p`, as in Nmap). It connects to each port, sends the baseline request, evaluates every rule on the response, and reports each match with product, family, extracted values such as brand or version, and confidence.
- **`athar convert`** turns rules into search-engine queries, to find candidates on the internet without scanning yourself. Each query is labelled `exact`, `approximate`, `superset` or `unsupported`, because engines tokenize text, lack operators or index only part of a body.
- **`athar match`** applies rules to data you already have, such as results exported from a search engine. It runs the exact rule logic, which removes the over-matches of approximate queries without sending a packet.

```bash
athar scan -r rules/ -p 80,443,8000-8100 10.0.0.0/24
```

For internet-wide hunting the commands can be combined: run a converted query in the engine, filter the export with `athar match`, then pass the remaining hosts to `athar scan` to confirm they are still live. That is one way to use them together, not a required order.

The **scanner defines what a rule means**. `match` and `scan` use the same evaluator as `verify`, so an engine query can be loose without making the results wrong.

`athar scan` and `athar verify` are available; `convert` and `match` are planned. See [CLI](#cli).

## Principles

1. **Simple.** One rule describes one service in one YAML file. Rules use Sigma's grammar rather than a new one. A feature goes into the format only when real rules need it, and [docs/decisions.md](docs/decisions.md) lists the ideas that are waiting for that.
2. **Engine-neutral.** A rule describes properties of a response, never engine syntax. Engine syntax lives in the converters, so a change like Censys's new query language gets fixed in one place.
3. **The scanner defines meaning.** Rule semantics are defined against the raw response. Engine queries are approximations that declare their fidelity.
4. **Passive first, active to confirm.** Rules that only use the baseline request (what engines index anyway) are fully convertible. Extra probes are opt-in, safe by construction, and make those parts active-only.
5. **Identify, don't just alert.** A match yields product, vendor, family, version and CPE, as Recog and Nmap do.
6. **Tested.** Every rule carries example responses that run as tests on every pull request, so an edit that breaks a rule cannot merge.
7. **Licence-clean.** Rules are shared under a permissive licence. Encumbered methods such as JA4S/JA4X are optional fields, never required.

## Scope

One rule matches **one service**: one IP address and one port. Fingerprints that only work when two ports of the same host are combined are deliberately left out of v0.1. [docs/decisions.md](docs/decisions.md#multi-service-fingerprints) explains why and how they could be added later without changing existing rules.

## Repository layout

```text
.
├── README.md               this file
├── spec/
│   └── athar-spec.md       the rule format (normative)
├── rules/                  the rule collection, one folder per category
│   ├── README.md           naming, required tests, rule template
│   └── offensive-tool/
├── cli/                    the athar command-line tool (Go)
│   └── README.md           commands, architecture, how to release
├── go.mod                  Go module for the CLI
├── scripts/
│   └── build-release.sh    builds the release archives
├── .github/workflows/      CI on every push; release build on version tags
└── docs/
    ├── prior-art.md        existing formats and what Athar takes from each
    ├── decisions.md        decided, open and deferred design questions
    └── images/
```

## CLI

`athar` is a single binary written in Go ([why Go](docs/decisions.md#cli-in-go)).

| Command | Status | What it does |
| --- | --- | --- |
| `athar scan` | available | Checks hosts, CIDR ranges and ports for services that match the rules; writes the matches as JSONL. |
| `athar verify` | available | Checks rules against the spec and runs every rule's tests. |
| `athar convert` | planned | Turns rules into FOFA, Shodan, Censys or ZoomEye queries, with fidelity and warnings. |
| `athar match` | planned | Evaluates rules against stored data (engine exports, recorded responses) without sending packets. |

### Install

Download the archive for your platform (Linux, macOS, Windows; amd64 and arm64) from the [latest release](https://github.com/Athar-HQ/Athar/releases/latest) and put `athar` on your `PATH`. `checksums.txt` in the release lists the SHA-256 of every archive. The binaries are not signed yet; on macOS, clear the quarantine flag once with `xattr -d com.apple.quarantine athar`.

Or build it with Go 1.25 or newer:

```bash
go install github.com/Athar-HQ/Athar/cli/cmd/athar@latest
```

### Scan

Give `athar scan` the rules, the ports and the targets: IP addresses, hostnames, CIDR ranges up to /16, or `host:port`. Flags can go before or after the targets.

```bash
athar scan -r rules/ -p 80,443,8000-8100 10.0.0.0/24
```

It connects to every host and port, fingerprints each open port (TLS certificate, `GET /`, favicon, banner) and prints one line per service that matches a rule. With `-v` it also lists every open port on stderr, with what it answered. On a terminal the output is coloured; `-no-color` or the `NO_COLOR` environment variable turns colours off.

A real scan from 25 November 2026. Infrastructure like this moves fast, so these hosts may answer differently by the time you read this.

![athar scan of 144.202.110.94:443 and 130.12.171.248:9443: the ARTEX variant rule matches an ARTEX console, the family rule matches an ARGOS console and extracts brand=ARGOS](docs/images/athar-scan.png)

- **130.12.171.248:9443** is an ARTEX console. The ARTEX variant rule matches both its title prefix and its favicon hash, so it replaces the family match.
- **144.202.110.94:443** is an ARGOS console behind a Caddy proxy with a Let's Encrypt certificate for the IP. The family rule matches and extracts the brand. The ARTEX variant rule does not, because neither the title prefix nor the favicon is ARTEX's.

An hour earlier the first host accepted connections but reset every request, perhaps because of a source-IP filter or a restart. `-v` showed it as:

```text
open 130.12.171.248:9443 no response (tried TLS, HTTP)
```

For tools, `-json` prints one JSON object per line instead, for example to pipe into `jq`:

```text
$ athar scan -r rules/ -json -timeout 10s 130.12.171.248:9443
{"target":"130.12.171.248:9443","tls":true,"rule":"0536c409-98ed-4d1d-8e07-7c80b39a4f53","title":"Agentic Offensive Framework - ARTEX","product":"ARTEX","family":"artex","category":"offensive-tool","confidence":"high","matched":["selection_brand","selection_icon","selection_route","selection_title"],"probes":["default"],"observed":"2026-11-25T08:18:27Z"}
```

| Flag | Effect |
| --- | --- |
| `-r` | Rule file or folder; repeat for more. Required. |
| `-p` | Ports, e.g. `22,80,443,8000-8100`. Without it, a built-in list of common ports plus the ports the rules list under `target.ports` (`athar scan -h` prints the list). |
| `-iL` | Read targets from a file, one per line; `-` reads stdin. |
| `-json` | Print matches as JSON lines instead of readable lines. |
| `-o` | Write the matches to a file instead of stdout, as readable lines or, with `-json`, JSON lines. |
| `-no-color` | No colours. Colours are also off when the output is not a terminal or `NO_COLOR` is set. |
| `-c`, `-per-host`, `-rate` | Parallel checks (50), parallel checks per host (8), new connections per second (200). |
| `-timeout` | Connect, handshake and read timeout (3s). |
| `-probes` | Also send the custom probes rules declare. Off by default. |
| `-v` | Print every open port to stderr, with what it answered. A port that accepts connections but answers nothing shows as `no response (tried TLS, HTTP)`. |

Only scan hosts you are allowed to scan. The scanner identifies itself in its HTTP `User-Agent` as `athar`.

### Verify rules

`athar verify` takes rule files or folders. It checks every rule against the spec (required fields, field names, modifiers, the condition) and runs the rule's `tests`:

```bash
git clone https://github.com/Athar-HQ/Athar.git
cd Athar
athar verify rules/
```

```text
rules/offensive-tool/aof_artex.yml        2/2 tests passed
rules/offensive-tool/aof_artex_artex.yml  3/3 tests passed

2 rules, 0 failed; 5/5 tests passed; 0 errors, 0 warnings
```

Use it while you write a rule. Here a test response lacks the body string the rule requires, and the rule has no negative test yet:

```text
$ athar verify c2/example_panel.yml
c2/example_panel.yml  FAIL  0/1 tests passed
  test "login page" failed: expected match, got no_match (selections that held: selection_title)
  warning: no test with expect: no_match

1 rule, 1 failed; 0/1 tests passed; 0 errors, 1 warning
```

| Flag | Effect |
| --- | --- |
| `-strict` | Warnings fail too: a missing positive or negative test, an unused selection, an unknown top-level key. This repository's CI runs `athar verify -strict rules`. |
| `-q` | Print only rules with problems, plus the summary. |
| `-no-color` | No colours, as for `scan`. |

Exit codes: `0` everything passed, `1` rule errors or failed tests, `2` usage or read error. `athar version` prints the version.

## Contributing rules

Rules live in [rules/](rules/), one folder per category. Every rule needs at least one positive and one negative test, a reference to the public source of the hunt, and no engine syntax outside the `native` section. [rules/README.md](rules/README.md) has the conventions and a template.

## Authors

- Florian Roth ([@cyb3rops](https://x.com/cyb3rops)): specification and CLI
- Gameel Ali ([@MalGamy12](https://x.com/MalGamy12)): rules and research

## Licence

Not decided yet. The proposal is the Detection Rule License (DRL) 1.1 for rules, as Sigma uses, and a permissive licence for the code. See [docs/decisions.md](docs/decisions.md#open).
