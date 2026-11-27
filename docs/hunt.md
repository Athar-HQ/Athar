# Design note: `athar hunt`

Status: proposal, not decided (2026-11-27). Nothing here is built. Discuss it in an issue before any code is written.

## The idea

Most new rules so far came from pivoting by hand. We searched an engine for a signal we trusted, looked through the results, and noticed hosts that matched it but looked different in some other field. The ARTEX rules grew this way: searches on the favicon and the family title turned up consoles with Portuguese, Russian and Chinese titles and rebrands such as NKW and AntiFox. Each became a new selection or a variant rule.

`athar hunt` would automate the routine part of that loop. It searches an engine with an existing rule and groups the stored records by field. It then reports values that no rule in the family covers yet, checks whether each one is specific to the product, and writes a draft rule for every candidate that passes. A person still decides what gets merged.

## Flow

```text
rule ──convert──▶ engine query ──API──▶ stored records ──normalise──▶ taxonomy fields
                                                                          │
           draft rules ◀── pivot check ◀── candidates ◀── compare with known values
```

1. **Pick seeds.** For each rule, take each selection that identifies the product on its own (a favicon hash, a default certificate name, a distinctive title) and turn it into one query with the existing converter. A rule's whole condition is a narrower seed. Selections with `confidence: medium` or lower are not seeds.
2. **Fetch.** Run the query through the engine's API and keep each record as the engine returned it, so a run can be replayed and tested without the API.
3. **Normalise.** Map each record onto taxonomy fields (`http.title`, `http.favicon.mmh3`, `http.headers.server`, `tls.cert.subject.cn`, `tls.jarm`, …). This is spec Appendix A run in reverse, field by field. That is different from turning a query back into a rule, which [AGENTS.md](../AGENTS.md) rules out, because a record states its values, while a query only says where to look. Fields an engine does not store stay absent, as in rule tests.
4. **Confirm.** Evaluate the seed rule on every normalised record with the same evaluator `athar verify` uses. Records the rule does not match are reported apart: they show where the engine's query is broader than the rule (a substring search, whole-word matching).
5. **Compare.** For each field, collect the values across matching records. A value is *known* if a rule in the same family (the seed, its `related` rules and every rule with the same `identifies.family` or `product`) matches it, or if it appears in those rules' `match` tests. Every other value that occurs often enough is a *candidate*.
6. **Pivot check.** Search for each candidate on its own and measure the overlap: the share of the candidate's hosts that also carry the seed signal. High overlap means the new value belongs to the product. Low overlap means it is generic (a stock nginx title, a shared CDN certificate) and only coincides with the product on a few hosts.
7. **Draft.** For each candidate that passes, write a rule from a template. It gets `status: experimental`, a fresh `id`, `related: variant-of` the family rule (or `similar` when there is no family), the pivot query under `native` and a selection on the new value. It also gets a `match` test built from one engine record and a `no_match` test from a record the candidate search returned without the seed signal. The tool runs `athar verify -strict` on every draft and drops those that fail.

## Noise

Passive data is noisy, and most of a hunt's output will be noise if nothing filters it.

- **Minimum support.** A candidate needs at least `-min-hosts` records (default 3) on different IPs. One-off values are usually a reverse proxy, an error page or a half-finished deployment.
- **Honeypots.** Some hosts answer every port with copied titles and favicons of many products. A record that matches rules of several unrelated families is dropped and listed separately.
- **Deployment details.** Values that describe the host rather than the product are not candidates: `http.headers.date`, `content-length`, session cookie values, certificates issued by Let's Encrypt for the host's own name. A built-in list of volatile fields covers most of them.
- **Generic values.** The pivot check removes them. A candidate whose overlap stays below `-min-overlap` (default 0.5) is reported as "co-occurs, not specific" with its counts, not drafted.

## Output

One JSON line per finding, like `athar scan -json`. Each line has `seed` (rule id and query), `engine`, `field`, `value`, `hosts`, `overlap`, `known` (the rule that covers it, if any), `verdict` (`new`, `generic`, `honeypot`, `engine-broader`) and `draft` (the path of the draft rule, if one was written). A text summary groups the findings by rule. `-o <folder>` writes the drafts. Hit counts go to the pull request description, as in [decisions.md](decisions.md#no-hit-counts-in-rules), never into a rule.

## What stays human

The tool proposes and a person approves. Someone still has to decide:

- whether a cluster is the same product, a fork, a lookalike or a honeypot;
- `confidence`, `category`, `description` and `author` (drafts leave `author` empty for the reviewer to fill; `verify` doesn't check it today);
- whether a candidate should become its own variant rule or another value in an existing selection.

## Engines

Start with one backend and add others behind a small interface: *search(query, fields) → records*, *count(query, facet) → value counts*, *field map*.

- **Shodan first.** [`/shodan/host/count`](https://developer.shodan.io/api) takes `facets` and costs no query credits, and [the facet list](https://www.shodan.io/search/facet) includes `http.title`, `http.favicon.hash`, `http.html_hash`, `ssl.cert.subject.cn` and `ssl.jarm`. Steps 5 and 6 can then mostly run on facet counts. Full records (`/shodan/host/search`, 100 per page) cost 1 credit for any query with a filter and 1 more per 100 results after the first page. They are only needed for test data and for fields without a facet, such as the `Server` header.
- **Modat second.** It is already a convert target, and `same_service()` keeps conditions on one service. Its API endpoint, the API access and limits on a free account, and whether it has aggregations still need to be checked; docs.modat.io did not resolve on 2026-11-27.
- Censys, FOFA, ZoomEye, urlscan.io and Hunt.io later, if someone asks. Each needs its own field map and credit handling.

## Safety and cost

- **Passive only.** The tool reads what engines have already stored and never connects to the hosts. To check a candidate live, run `athar scan` separately, only against targets you are allowed to probe.
- **Keys from the environment** (`SHODAN_API_KEY`, `MODAT_API_KEY`), never from flags, rule files or output.
- **A credit budget.** `-max-credits` (default low) stops a run before it spends more than this. A dry run, `-plan`, prints the queries and their estimated cost without sending them.
- **A cache.** Raw engine responses are stored on disk with the query and date, so repeated runs and tests don't spend credits.

## Relation to other plans

- The [planned `athar match`](conversion-targets.md#reachable-without-a-new-backend) runs rules on recorded responses. Steps 3 and 4 are the same thing for engine records, so the two should share the normaliser and the record format.
- The [baseline probe](decisions.md#open) question matters here too: if an engine fetched with a different Host header or followed redirects, its title is not what `athar scan` sees. Drafts should say which engine their test data came from.

## Open questions

1. Is one value per field the right unit, or should candidates be combinations, such as a new title together with a new favicon?
2. How should overlap be measured when the seed signal is not stored by the engine the candidate was found on?
3. Should drafts go into `rules/` on a branch, or into a separate review folder that `verify` skips?
4. Where should the list of volatile fields live: in the CLI or in the spec next to the taxonomy?
5. Is "hunt" the right name? [decisions.md](decisions.md#huntio-as-a-convert-target) already avoids `hunt` as a target name because it is an everyday word; `athar pivot` is the alternative.

## First milestone

`athar hunt -engine shodan -plan` and a real run for one rule family (ARTEX), on facet counts only, with JSON output and no drafts. If it finds the variants we already found by hand, it works, and draft writing comes next.
