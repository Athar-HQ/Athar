# Conversion targets

`athar convert` turns rules into queries for search engines and into templates for other scanners, so a rule can run where people already hunt. This page lists what it supports, which targets come next and which were looked at and set aside (assessed in November 2026 from each tool's documentation and source). To ask for a target, or to offer to build one, open an issue.

## Supported

| Target | Output | Notes |
| --- | --- | --- |
| FOFA, Shodan, Censys, ZoomEye, Modat Magnify, urlscan.io, Hunt.io | Search queries | Find candidates in indexed scan data. See [spec section 10](../spec/athar-spec.md#10-conversion). |
| [Nuclei](https://github.com/projectdiscovery/nuclei) | One template per rule (`-t nuclei`) | Runs the rule in Nuclei without Athar's scanner. The condition becomes one DSL matcher. Favicon rules are approximate, because the template fetches `/favicon.ico` while the scanner first follows `<link rel="icon">`. Body hash rules are approximate too: Nuclei also hashes a body that was cut short. |
| [Nmap NSE](https://nmap.org/book/nse.html) | One script, `athar.nse`, plus one data file per rule (`-t nse`) | Runs the rules with `nmap --script`. The script probes and matches as Athar's scanner does, regular expressions included, so every rule in the repository converts exactly; a test compares the two on the same responses. Not converted: TLS version, cipher and ALPN, JARM, JA3S, certificate DN and `self_signed`. |

### Reachable without a new backend

- [BBOT](https://github.com/blacklanternsecurity/bbot) runs Nuclei templates from a folder through its [nuclei module](https://github.com/blacklanternsecurity/bbot/blob/stable/bbot/modules/nuclei.py) (`modules.nuclei.templates`). [TscanPlus](https://github.com/TideSec/TscanPlus) and [nemo_go](https://github.com/hanc00l/nemo_go) run Nuclei templates too.
- [uncover](https://github.com/projectdiscovery/uncover) runs search-engine queries, including the ones `athar convert` writes.
- Tools that only collect responses, such as [ZGrab2](https://github.com/zmap/zgrab2), [tlsx](https://github.com/projectdiscovery/tlsx) and httpx with `-json`, have no matcher to convert to. Their output fits the planned `athar match` better: it would run the rules' exact logic on the recorded responses.

## Candidates

In the order they should be built.

| Target | Format | What would convert | What would not | Fit |
| --- | --- | --- | --- | --- |
| [afrog](https://github.com/zan8in/afrog) | YAML PoCs: requests and a [CEL expression](https://github.com/zan8in/afrog/blob/main/docs/en/poc/02-syntax.md) | Body, headers and status; title as a regex over the body; favicon mmh3 (Shodan algorithm) and other hashes; file hashes from custom probes; any AND, OR and NOT | Certificate fields | Good, and cheap next to the Nuclei backend. [fscan](https://github.com/shadow1ng/fscan) says it loads afrog PoCs too (not checked). |
| [Suricata](https://docs.suricata.io/en/latest/rules/http-keywords.html) | IDS rules | Title (as a regex), body, headers and status of HTTP responses; certificate subject, issuer, SAN and SHA-1 on TLS 1.2 and older ([TLS keywords](https://docs.suricata.io/en/latest/rules/tls-keywords.html)); JA3S; SSH banners | Favicon hashes, SHA-256 certificate fingerprints, JARM, anything inside HTTPS or TLS 1.3 | Later, once there are C2 or banner rules. It spots these services in traffic instead of scanning for them. Tests can replay synthetic pcaps with `suricata -r`. |
| [Nmap service probes](https://nmap.org/book/vscan-fileformat.html) | `match` lines, one regex over the raw reply to a probe | Banners, with version extraction; title, header and body as one regex over the reply to `GET / HTTP/1.0` without a `Host` header | Favicons, certificates, hashes | Later, for banner rules. `--versiondb` replaces Nmap's own file, so ours runs as a second pass; [naabu](https://github.com/projectdiscovery/naabu) loads it with `-sV-probes`. The [NPSL](https://svn.nmap.org/nmap/LICENSE) (section 3) covers software that reads Nmap's data files, so we ship only our own lines. |
| [Rapid7 Recog](https://github.com/rapid7/recog) | XML, one regex per field | Title, `Server` and `WWW-Authenticate` headers, certificate subject and issuer, JARM, SSH and FTP banners | AND across fields, body, favicon mmh3 (Recog uses MD5), hashes | Later, for banner rules. [runZero](https://help.runzero.com/docs/using-custom-fingerprints/) and [InsightVM](https://docs.rapid7.com/insightvm/sending-custom-fingerprints-to-paired-scan-engines/) load custom Recog files; Metasploit uses Recog but loads only its bundled files. |

## Looked at, not planned

| Tool | Why not |
| --- | --- |
| [FingerprintHub](https://github.com/0x727/FingerprintHub) / [observer_ward](https://github.com/emo-crab/observer_ward) | No title or certificate variables. observer_ward checks a template's favicon matchers apart from its other matchers ([cluster.rs](https://github.com/emo-crab/observer_ward/blob/main/engine/src/template/cluster.rs)), so a favicon combined with AND or NOT changes meaning. Our Nuclei templates don't run in it: it lacks `req-condition` and DSL extractors. |
| Wappalyzer forks ([webappanalyzer](https://github.com/enthec/webappanalyzer), [wappalyzergo](https://github.com/projectdiscovery/wappalyzergo), [webanalyze](https://github.com/rverton/webanalyze)) | A technology's patterns are alternatives, so there is no AND. No title, favicon or certificate fields. |
| [WhatWeb](https://github.com/urbanadventurer/WhatWeb) | Plugins are Ruby code that runs inside a GPL program. Favicon checks need aggressive mode, and there are no certificate fields. |
| [httpx](https://github.com/projectdiscovery/httpx) `-mdc` | One rule per run, and the output doesn't say which rule matched. Nuclei covers the same. |
| [Metasploit](https://github.com/rapid7/metasploit-framework) | No fingerprint data that users can extend for HTTP; every rule would be a Ruby module. |
| [OpenVAS / Greenbone](https://github.com/greenbone/openvas-scanner) | Every rule would be a NASL script under the GPL, loading one means turning off signature checks, and a real-tool test needs most of the Greenbone stack. |
| [fingerprintx](https://github.com/praetorian-inc/fingerprintx) / [Nerva](https://github.com/praetorian-inc/nerva) | Fingerprints are Go code; there is no way to load your own. fingerprintx is archived. |
| [Zeek](https://docs.zeek.org/en/master/frameworks/signatures.html) | Signatures have no TLS conditions, and scripts would be code per rule. Suricata comes first. |
| [chainreactors fingers](https://github.com/chainreactors/fingers) (gogo, spray), [Nikto](https://github.com/sullo/nikto) user databases, [hfinger](https://github.com/HackAllSec/hfinger), [Burp BChecks](https://portswigger.net/burp/documentation/scanner/bchecks/bcheck-definition-reference) | Watched, not planned. fingers matches any one pattern, with no AND or NOT. Nikto knows only MD5 favicons and no certificates. hfinger fits Athar closely but has few users. BChecks needs a Burp Pro licence to test. |
