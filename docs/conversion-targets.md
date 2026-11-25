# Conversion targets

`athar convert` turns rules into queries for search engines and into templates for other scanners, so a rule can run where people already hunt. This page lists what it supports and which targets could come next. To ask for one, or to offer to build it, open an issue.

## Supported

| Target | Output | Notes |
| --- | --- | --- |
| FOFA, Shodan, Censys, ZoomEye, Modat Magnify, urlscan.io | Search queries | Find candidates in indexed scan data. See [spec section 10](../spec/athar-spec.md#10-conversion). |
| [Nuclei](https://github.com/projectdiscovery/nuclei) | One template per rule (`-t nuclei`) | Runs the rule in Nuclei without Athar's scanner. The condition becomes one DSL matcher. Favicon rules are approximate, because the template fetches `/favicon.ico` while the scanner first follows `<link rel="icon">`. |

## Candidates

Each candidate is a scanner or format that people already run. They are ordered by how well Athar rules fit them.

| Target | Format | What would convert | What would not | Fit |
| --- | --- | --- | --- | --- |
| [FingerprintHub](https://github.com/0x727/FingerprintHub) (observer_ward) | Nuclei-like YAML | Probably most of what converts to Nuclei | To be checked against the format | Good, likely cheap next to the Nuclei backend |
| [Nmap service probes](https://nmap.org/book/vscan-fileformat.html) | `match` lines in `nmap-service-probes` | Title, header and banner rules, as one regex over the raw response; `identifies` and `extract` map to `p/`, `v/` and `cpe:` | Favicon hashes and certificate fields. Header and body conditions together need regex lookaheads. | Medium. Nmap's licence covers software that reads the probes file; check that it allows generating entries before building this. |
| [Nmap NSE](https://nmap.org/book/nse.html) | A Lua script per rule | Everything the Nuclei backend converts | Nothing in principle, but every rule becomes generated code, and the favicon's mmh3 hash needs a Lua implementation | Low: much more code than a data format |
| [Rapid7 Recog](https://github.com/rapid7/recog) | XML, one regex per field | Rules with a single field: title, Server header, favicon | Rules that combine fields | Low |
| [Wappalyzer forks](https://github.com/enthec/webappanalyzer) (httpx `-td`) | JSON per technology | Header, HTML and cookie patterns | AND: a technology's patterns are alternatives, so rules that need two signals become supersets. No certificate fields. | Low |
| Suricata, Zeek | IDS rules, scripts | HTTP response and certificate fields seen in traffic | Favicon hashes and custom probes. The use differs: spotting these services in network traffic, not scanning for them. | Later |
