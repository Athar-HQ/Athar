# Rules

Each file is one Athar rule describing one network service. The format is defined in [spec/athar-spec.md](../spec/athar-spec.md). To turn a search-engine query into a rule, or to let an AI agent do it, see [AGENTS.md](../AGENTS.md).

## Layout

One folder per category, using the controlled category list from the spec:

```text
rules/
├── c2/
│   ├── adaptixc2_page_nov26.yml                    AdaptixC2 page
│   ├── asyncrat_cert_nov26.yml                     AsyncRAT default server certificate
│   ├── cobaltstrike_cert_nov26.yml                 Cobalt Strike default certificates
│   ├── cobaltstrike_cert_sha256_nov26.yml          Cobalt Strike certificate fingerprints
│   ├── covenant_cert_nov26.yml                     Covenant default certificate
│   ├── covenant_title_nov26.yml                    Covenant web console title
│   ├── cyberc2_title_nov26.yml                     CyberC2 title
│   ├── dcrat_cert_nov26.yml                        DcRat default server certificate
│   ├── deimos_page_nov26.yml                       DeimosC2 Go 404 page and example certificate
│   ├── desredteam_favicon_nov26.yml                DesRedTeam favicon
│   ├── desredteam_title_nov26.yml                  DesRedTeam and DesShell title
│   ├── geacon_pro_cert_nov26.yml                   Geacon_Pro certificate
│   ├── hak5_cloud_c2_favicon_nov26.yml             Hak5 Cloud C2 favicon
│   ├── hak5_cloud_c2_page_nov26.yml                Hak5 Cloud C2 page hashes
│   ├── hak5_cloud_c2_title_nov26.yml               Hak5 Cloud C2 title
│   ├── havoc_page_nov26.yml                        Havoc 404 page
│   ├── hypeagent_cert_nov26.yml                    HypeAgent C2 certificate
│   ├── metasploit_cert_nov26.yml                   Metasploit self-signed CA certificate
│   ├── mythic_cert_nov26.yml                       Mythic certificate organisation
│   ├── netsupport_server_header_nov26.yml          NetSupport Gateway server header
│   ├── nighthawk_response_nov26.yml                Nighthawk C2 default response
│   ├── nimplant_server_header_nov26.yml            NimPlant listener server header
│   ├── obsidianstrike_title_nov26.yml              ObsidianStrike C2 title
│   ├── oyster_page_nov26.yml                       Oyster backdoor page hash
│   ├── pivotc2_body_nov26.yml                      Pivot-C2 response body marker
│   ├── pivotc2_cert_nov26.yml                      Pivot-C2 certificate
│   ├── poshc2_cert_nov26.yml                       PoshC2 default certificate issuer
│   ├── pupy_cert_nov26.yml                         Pupy RAT certificate pattern
│   ├── purerat_cert_nov26.yml                      PureRAT agent certificate
│   ├── pyramid_headers_nov26.yml                   Pyramid C2 default authentication headers
│   ├── ransomhub_python_c2_page_nov26.yml          RansomHub Python C2 page
│   ├── rogue_c2_body_nov26.yml                     Rogue C2 page
│   ├── salt_typhoon_ssh_banner_nov26.yml           Salt Typhoon ClosedSSH banner
│   ├── sliver_cert_nov26.yml                       Sliver multiplayer certificate
│   ├── smokedham_page_nov26.yml                    SMOKEDHAM page hashes
│   ├── spacex1337_title_nov26.yml                  Space X 1337 C2 login title
│   ├── supershell_page_nov26.yml                   Supershell C2 page
│   ├── tuoni_cert_nov26.yml                        Tuoni C2 certificate
│   ├── viper_favicon_nov26.yml                     Viper C2 favicon
│   ├── viper_title_nov26.yml                       Viper C2 page
│   ├── voidlink_basic_auth_nov26.yml               VoidLink C2 Basic auth realm
│   ├── vshell_favicon_nov26.yml                    Vshell C2 favicon
│   └── vshell_title_nov26.yml                      Vshell C2 management platform
├── malware-panel/
│   ├── hookbot_favicon_nov26.yml                   HookBot panel favicon
│   ├── hookbot_title_nov26.yml                     HookBot panel
│   ├── matanbuchus_title_nov26.yml                 Matanbuchus panel login
│   ├── meduza_favicon_nov26.yml                    Meduza Stealer panel favicon
│   ├── meduza_title_nov26.yml                      Meduza Stealer panel
│   └── stealc_v2_page_nov26.yml                    StealC v2 panel page hash
├── offensive-tool/
│   ├── aof_ai_infra_guard_favicon_nov26.yml        AI-Infra-Guard favicon
│   ├── aof_ai_infra_guard_page_nov26.yml           AI-Infra-Guard web console page
│   ├── aof_artex_nov26.yml                         family rule
│   ├── aof_artex_antifox_nov26.yml                 AntiFox variant
│   ├── aof_artex_artex_favicon_nov26.yml           ARTEX favicon
│   ├── aof_artex_artex_nov26.yml                   ARTEX variant
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
│   ├── aof_cairn_body_nov26.yml                    Cairn upstream console
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
│   ├── aof_vulnhunter_body_nov26.yml               VulnHunter body mention
│   ├── aof_vulnhunter_favicon_nov26.yml            VulnHunter favicon
│   ├── aof_vulnhunter_title_nov26.yml              VulnHunter title and body
│   ├── aof_xalgorix_nov26.yml                      Xalgorix dashboard title
│   ├── burp_collaborator_server_nov26.yml          Burp Collaborator server header
│   ├── chisel_server_nov26.yml                     Chisel server, health and version endpoints
│   ├── frp_not_found_page_nov26.yml                frp server not-found page
│   ├── goshs_server_header_nov26.yml               goshs server header, with version
│   ├── interactsh_body_nov26.yml                   Interactsh server landing page
│   ├── ligolo_ng_cert_nov26.yml                    Ligolo-ng certificate organisation
│   ├── mitmproxy_server_header_nov26.yml           mitmproxy server header, with version
│   ├── pywssocks_page_nov26.yml                    Pywssocks server page
│   ├── responder_smb_nov26.yml                     Responder SMB server GUID
│   ├── reverse_ssh_cert_nov26.yml                  reverse_ssh certificate
│   ├── spiderfoot_favicon_nov26.yml                SpiderFoot icon, MurmurHash3
│   ├── spiderfoot_favicon_sha256_nov26.yml         SpiderFoot icon, SHA-256
│   ├── spiderfoot_title_nov26.yml                  SpiderFoot web interface title, with version
│   ├── sqlmap_api_nov26.yml                        sqlmap REST API server
│   ├── updog_page_nov26.yml                        updog file server page
│   └── wstunnel_page_nov26.yml                     wstunnel default page and certificate
├── phishing-kit/
│   ├── 365stealer_body_nov26.yml                   365-Stealer panel
│   ├── devilginx_title_nov26.yml                   Devilginx title
│   ├── evilginx_cert_nov26.yml                     Evilginx API certificate organisation
│   ├── evilginx_title_nov26.yml                    Evilginx and evilgophish title
│   ├── gophish_cert_nov26.yml                      Gophish admin default certificate
│   └── gophish_redirect_nov26.yml                  Gophish admin login redirect
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
