# Instructions for AI agents

This file tells coding agents (Claude Code, Codex, Cursor, Copilot, Gemini CLI and others) how to work with Athar rules and the `athar` CLI. People can read it too.

Athar rules are YAML files that describe one network service each: one IP address and one port. The format is defined in [spec/athar-spec.md](spec/athar-spec.md), which is normative. Repository conventions, the pull-request checklist and a rule template are in [rules/README.md](rules/README.md). Read both before writing a rule.

## Get the CLI

Use a release binary from <https://github.com/Athar-HQ/Athar/releases/latest>, or build it:

```bash
go install github.com/Athar-HQ/Athar/cli/cmd/athar@latest
```

Inside this repository, `go run ./cli/cmd/athar <command>` works without installing.

| Command | Use it to |
| --- | --- |
| `athar verify -strict <rule or folder>` | Check a rule against the spec and run its tests. Run it after every edit. Exit code 0 means pass. |
| `athar convert -json -t <engines> <rule>` | Turn a rule into search-engine queries (`fofa`, `shodan`, `censys`, `zoomeye`, `modat`, `urlscan`), a Nuclei template (`nuclei`) or a data file for the Nmap script `athar.nse` (`nse`); `-o <folder>` writes the files, for `nse` with `athar.nse`. One JSON object per rule and target with `query` or `template`, `fidelity` and, when something was lost, `notes`. |
| `athar scan -json -r <rules> [-p ports] <targets>` | Probe hosts and print one JSON line per matching service. Sends network traffic; see "Scanning" below. |

Add `-no-color` (or set `NO_COLOR=1`) when you parse text output. Exit codes for all commands: `0` success, `1` failed rules or tests, `2` usage or read error.

## Turn a search-engine query into a rule

Most hunts start as a query on FOFA, Shodan, Censys, ZoomEye, Modat Magnify or urlscan.io. There is no reverse converter in the CLI on purpose: a query says where an engine found something, not what the service looks like, and the mapping needs judgement. Follow these steps.

1. **Get the query and at least one real response.** Ask the user for the engine, the exact query and, if possible, one host it found. The engine's stored record for that host (title, headers, body excerpt, favicon hash, certificate) is the best source. Only fetch a host yourself if the user tells you to, and then only with a plain `GET /`, for example `curl -sk -i https://<host>:<port>/`.
2. **Map every filter to a taxonomy field** with the table below. Choose the field from what the response shows, not from the query text: a bare keyword in the query usually sits in the title or body, and the response tells you which. Keep the rule's meaning close to the query. Add a signal the query doesn't have only to replace a label (step 5) or when the user asks for a tighter rule, and say so.
3. **Fix the operator.** Engines differ: FOFA's `title="x"` is a substring match, while a bare value in Athar is an exact match. Use `|contains` for substring searches, a bare value only when the engine query was an exact match (`==`, Censys and Modat `=`), and `|re` for regex searches. Athar matching is case-insensitive unless you add `|cased`.
4. **Turn negations into filters.** `!=`, `-field:value`, `not` and `NOT` become a selection named `filter_<what>` and `and not filter_<what>` in the condition. A negated header value goes to `http.headers_raw`, since the response can't show which header the value would have been in. Keep negations that exclude lookalikes or other brands, such as the original favicon when the rule is about rebrands. A negation that only excludes a deployment detail, such as `nginx` in the headers of instances behind a reverse proxy, narrows the hunt but makes the scanner miss real instances: drop it and tell the user, unless they want it kept.
5. **Leave out what is not about the service.** Location and ownership filters (`country`, `org`, `asn`, `city`, `domain`, `hostname`, `ip`, `net`) narrow a hunt but don't describe a product; drop them. Engine-proprietary labels (FOFA `app` and `fid`, Shodan `product` and `http.component`, Censys labels and `software`, Modat `fingerprints` and `tag`, urlscan verdicts and brands) are not taxonomy fields. If another filter in the query already identifies the product, drop the label. Otherwise replace it with what the product sets by default in the response: a cookie name, a favicon, a generator tag. Several signals that each identify the product on their own go into one selection as a list of maps, which matches any of them. Which signal a label stands for is your guess, so tell the user what you chose. Keep the original query under `native`.
6. **Ports are a hint.** A port filter (`port:`, `port=`, `port =`) becomes `target.ports`, which makes the converted query broader than the original; tell the user. Use `service.port` in a selection only if the port itself identifies the service.
7. **Write tests.** At least one `match` test built from the real response and one `no_match` test that is a near miss: a similar title or a generic page the rule must reject. Tests list taxonomy fields under `response` (spec section 9), and fields a test doesn't list are absent. In particular, `http.headers_raw` is not built from `http.headers.<name>`: if the rule reads it, give it as received, the status line and every header line, each ending in `\r\n`. An engine's stored record, body excerpts included, is acceptable test data while the rule is `experimental`; say so in a comment.
8. **Fill the metadata** from the template in [rules/README.md](rules/README.md): a fresh lowercase UUIDv4 (`python3 -c 'import uuid; print(uuid.uuid4())'`), `status: experimental`, today's `date`, `references` to the public source of the hunt, and the original query under `native`, keyed by engine. Ask the user for `author`; don't invent one.
   - `identifies` needs at least a `product` or a `family`. Use `product` (and `vendor`, if you know it) for one product, and `family` for one codebase that ships under several brands (spec section 8).
   - `category` must come from the controlled list in spec section 7, and the tag `category.<category>` repeats it. If no category fits, tell the user instead of forcing one: a new category is the maintainers' decision.
9. **Verify and round-trip.** Run `athar verify -strict <file>` until it passes. Then run `athar convert -t <engine> <file>` for the engine the query came from and compare its query with the original. Explain every difference to the user: a dropped location or port filter, a label replaced by a signal, a `contains` that was an exact match. The fidelity `athar convert` reports compares the converted query with the rule, not with the original query. `approximate` without a note means the engine matches whole words (Shodan, Censys `:`) or that its equality is case-sensitive (ZoomEye `==`). A note that a mapping "is not verified" marks an engine field that spec Appendix A lists with †, such as FOFA `status_code=`: the query is labelled `approximate` even when it equals the original.
10. **Save the rule.** In this repository, rules go to `rules/<category>/`, named after the product as described in [rules/README.md](rules/README.md); a narrower rule adds a qualifier, such as `gitea_default_title.yml`. Elsewhere, save it where the user wants.

### Engine syntax to Athar fields

Values in angle brackets are placeholders. "contains" means `field|contains: value`; "exact" means `field: value`.

| Engine query | Athar selection |
| --- | --- |
| FOFA, ZoomEye `title="x"` · Shodan `http.title:"x"` · Censys `…http.html_title: "x"` · Modat `http.title~"x"` · urlscan `page.title:"x"` or `page.title.keyword:/.*x.*/` | `http.title` contains `x` |
| FOFA, ZoomEye `title=="x"` · Censys `…http.html_title = "x"` · Modat `http.title="x"` | `http.title` exact `x` |
| Censys `=~` · Modat `=~` (case-insensitive) · urlscan `/regex/` on a `.keyword` field | `http.title\|re`, with `(?i)` where the engine ignored case; urlscan regexes are anchored at both ends |
| Modat `==`, `~~`, `==~` | the same with `\|cased` added |
| FOFA `body=` · ZoomEye `http.body=` · Shodan `http.html:` · Censys `…http.body` · Modat `http.body~` | `http.body` contains |
| FOFA `header=` · ZoomEye `http.header=` | `http.headers_raw` contains, or `http.headers.<name>` if the response shows which header holds it |
| FOFA `server=` · ZoomEye `http.header.server=` · Modat `http.headers: (key = "Server" and value ~ "x")` · urlscan `page.server:` | `http.headers.server` contains |
| Modat `http.headers: (key = "<Name>" and value = "x")` · Censys `…http.headers` key and value | `http.headers.<name>` (lowercase name), exact for `=`, contains for `~` or `:`. `athar convert` doesn't write Censys header searches yet (the field is unverified), so on Censys the round trip drops them. |
| FOFA, ZoomEye `status_code=` · Shodan `http.status:` · Modat `http.status_code=` · urlscan `page.status:` | `http.status_code` exact |
| FOFA `icon_hash=` · Shodan `http.favicon.hash:` · ZoomEye `iconhash=` with an integer · Modat `http.files.mmh3=` | `http.favicon.mmh3` exact |
| ZoomEye `iconhash=` with 32 hex characters | `http.favicon.md5` exact |
| Censys `…http.favicons.hash_sha256` · Modat `http.files.sha256` | `http.favicon.sha256` exact |
| Shodan `http.html_hash:` · Modat `http.body_mmh3` | `http.body.mmh3` exact |
| FOFA `body_hash=` | No field: its algorithm is undocumented ([docs/decisions.md](docs/decisions.md)). Tell the user, keep the query under `native` and match on another signal; `athar convert` doesn't write `body_hash=`. |
| urlscan `hash:<sha256>` | A file the page loaded. Ask for the file's path (urlscan lists it under the scan's requests), declare a custom probe that fetches it, and match `http.body.sha256` in a selection with `probe: <id>`. See spec section 9 and `rules/offensive-tool/aof_artex_frontend_files_nov26.yml`. If the file is the favicon or the landing page itself, use `http.favicon.sha256` or `http.body.sha256` without a probe. |
| FOFA `cert.subject.cn=` · Shodan `ssl.cert.subject.cn:` · ZoomEye `ssl.cert.subject.cn=` · Modat `tls.subject.common_name` · Censys `…cert.parsed.subject.common_name` | `tls.cert.subject.cn` contains (exact for `==` or `=`) |
| The same with `issuer` | `tls.cert.issuer.cn` |
| Censys `…cert.fingerprint_sha256` · Modat `tls.fingerprint_sha256` | `tls.cert.sha256` exact |
| Shodan `ssl.cert.fingerprint:` | `tls.cert.sha256` exact for 64 hex characters, `tls.cert.sha1` for 40. Which hash Shodan stores there is not checked, so `athar convert` doesn't write it and the round trip on Shodan drops it. |
| FOFA `jarm=` · Shodan `ssl.jarm:` · ZoomEye `ssl.jarm=` · Censys `…jarm.fingerprint` · Modat `tls.jarm` | `tls.jarm` exact |
| Shodan `ssl.ja3s:` · ZoomEye `ssl.ja3s=` · Modat `tls.ja3s` | `tls.ja3s` exact |
| FOFA, ZoomEye `banner=` · Censys `…banner` · Modat `banner~` | `service.banner` contains |
| Bare quoted text (FOFA, ZoomEye, Shodan, Modat) | The field where the response shows the text (`http.title`, `http.body`, `http.headers.<name>`, `service.banner`). Use a `keywords` selection only if you can't tell. |
| `port` on any engine | `target.ports` |
| FOFA, ZoomEye `&&`, `\|\|` · Censys, Modat `and`, `or` · urlscan `AND`, `OR` · Shodan space (AND) and `field:"a","b"` (any of the values) | Several fields in one selection are AND; a list of values is OR; a list of maps (several field-value pairs, each starting with `-`) is OR across fields; separate selections combine in `condition` |
| Censys `host.services: (…)` · Modat `same_service(…)` | One rule; all of its selections already hold on one service. A Censys or Modat host query without these may combine two services of one host, which one rule can't express (spec section 11); ask the user which service the rule is about. |

Field names follow spec section 5 and Appendix A. If a filter has no row here and no field in the spec, tell the user rather than inventing a field.

### Worked example

The FOFA query behind `rules/offensive-tool/aof_artex_rebrands_nov26.yml`:

```text
("Autonomous penetration testing" && body="/function/tasks") && icon_hash!="-576220750"
```

- `"Autonomous penetration testing"` is bare text. The console's response has it in the title, `ARTEX — Autonomous Penetration Testing Console`, so it becomes `http.title|contains`.
- `body="/function/tasks"` becomes `http.body|contains: '/function/tasks'`. (The rule in the repository leaves it out: the title is specific enough, and Shodan doesn't index that part of the page.)
- `icon_hash!="-576220750"` becomes a filter:

```yaml
detection:
  selection_title:
    http.title|contains: 'Autonomous Penetration Testing Console'
  selection_body:
    http.body|contains: '/function/tasks'
  filter_artex_icon:
    http.favicon.mmh3: -576220750
  condition: selection_title and selection_body and not filter_artex_icon
native:
  fofa: '("Autonomous penetration testing" && body="/function/tasks") && icon_hash!="-576220750"'
```

`athar convert -t fofa` on that rule gives `title="Autonomous Penetration Testing Console" && body="/function/tasks" && icon_hash!="-576220750"` (exact). The difference to tell the user: the bare keyword, a full-text search, became a title search, which finds fewer hosts but only consoles.

## Write a rule from a response or a write-up

The same steps apply without a query: take the most specific stable signals the service shows on the baseline probe (`GET /`, the TLS handshake, the banner), in this order of preference: a distinctive title or body string, a favicon hash, a certificate field, a header. Prefer signals that survive rebrands and version updates. A custom probe (spec section 4) is only for services that can't be identified from the baseline, or to check the hash of a file the page loads; probes use GET, HEAD or OPTIONS, no credentials and no payloads.

A product with rebrands gets a family rule plus variant rules (spec section 8): the family matches what all brands share and extracts the brand; a variant links to the family with `related` type `variant-of` and repeats the family's selections.

`confidence` says how likely a match is really this service and not a lookalike: `certain` for unique hashes or certificates, `high` for a distinctive title or phrase, `medium` for signals other software could share, `low` for weak hints.

## Scanning

`athar scan` connects to every host and port it is given. Only scan targets the user owns or is authorised to test, and only when the user asks for a scan. Keep the default rate limits. `-probes` sends the custom probes that rules declare; leave it off unless the user wants it. Use `-json` and parse one record per line: `target`, `tls`, `rule`, `title`, `family`, `category`, `extracted`, `confidence`, `matched` (the selections that held), `probes`, `observed`.

## Change this repository

- Rules go to `rules/<category>/`, file names as in [rules/README.md](rules/README.md). Add the rule to the layout list there.
- Go code is in `cli/` (module at the repository root, Go 1.25+). Before you finish, run what CI runs:

  ```bash
  gofmt -l . && go vet ./... && go test ./... && go run ./cli/cmd/athar verify -strict rules
  ```

- Behaviour changes go into the docs in the same change: [README.md](README.md), [cli/README.md](cli/README.md), and the spec if the rule format changes. The README's "A rule" example is tested against the rule it links to.
- Design decisions and open questions are in [docs/decisions.md](docs/decisions.md). Don't change the rule format without the maintainers' agreement; open an issue instead.
- Published rule `id`s never change.
- Rules are licensed under the [Detection Rule License 1.1](LICENSE.Detection.Rules.md). When you copy or adapt a rule, keep its `author` and add your own; when you report matches, name the rule's author.
