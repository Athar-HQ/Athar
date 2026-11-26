package convert

import (
	"fmt"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"go.yaml.in/yaml/v3"

	"github.com/Athar-HQ/Athar/cli/internal/fields"
	"github.com/Athar-HQ/Athar/cli/internal/rule"
)

// nucleiTarget is the name -t takes.
const nucleiTarget = "nuclei"

// DRLURL is where the Detection Rule License 1.1 is published.
const DRLURL = "https://github.com/SigmaHQ/Detection-Rule-License"

// ref marks a field reference in a rendered term. The layout (how many
// requests, whether there is an ssl block) is only known once every term is
// rendered, so references are resolved afterwards.
const refStart, refEnd = "\x00", "\x01"

func ref(name string) string { return refStart + name + refEnd }

var refRe = regexp.MustCompile("\x00([^\x01]*)\x01")

// nuclei turns a rule into a Nuclei template. The rule's condition becomes
// one DSL matcher, so any boolean structure carries over; the fields the
// evaluator reads are rebuilt from what Nuclei exposes:
//
//   - http.title: an internal extractor computes it as the scanner does,
//     from the first <title>, entity-decoded and whitespace-collapsed.
//   - certificate fields: an ssl block runs before the http block, whose
//     matcher reads them as ssl_*.
//   - favicon hashes: a second request to /favicon.ico.
//   - custom HTTP probes: one more request each.
//
// Several requests run with req-condition, so the matcher can read body_2
// and the like, and it is guarded by the last request's status, so it is
// only evaluated once every response is in. Fields that may be missing from
// a response get empty defaults under variables, because Nuclei refuses to
// evaluate an expression with an undefined name.
//
// Terms are rendered with references such as ref("default/body"); which
// requests the template sends follows from the references left in the
// final expression.
type nuclei struct{ r *rule.Rule }

func (n *nuclei) andOp() string        { return " && " }
func (n *nuclei) orOp() string         { return " || " }
func (n *nuclei) canOr() bool          { return true }
func (n *nuclei) wrap(q string) string { return q }

var nucleiHeaderRe = regexp.MustCompile(`^[a-z0-9-]+$`)

// faviconReq names the favicon request; # can't start a probe id.
const faviconReq = "#favicon"

const nucleiFaviconNote = "the favicon is fetched from /favicon.ico; the scanner first follows <link rel=\"icon\">"

// term renders one condition as a DSL expression with field references.
func (n *nuclei) term(t term) (string, Fidelity, string, bool) {
	return n.render(t, "default")
}

// probeTerm handles conditions on a custom probe's response.
func (n *nuclei) probeTerm(t term) (string, Fidelity, string, bool) {
	p, ok := n.r.Probes[t.probe]
	if !ok || p.Request == nil {
		return "", 0, fmt.Sprintf("%s uses the custom probe %q, which is not an HTTP request", describe(t), t.probe), false
	}
	return n.render(t, t.probe)
}

func (n *nuclei) render(t term, probe string) (string, Fidelity, string, bool) {
	at := func(name string) string { return ref(probe + "/" + name) }
	no := func(why string) (string, Fidelity, string, bool) {
		return "", 0, fmt.Sprintf("%s: %s", describe(t), why), false
	}
	if t.field == "" {
		// A keyword is searched in the banner, the header block and the
		// body; Nuclei's HTTP response has no banner.
		pos := t
		pos.negated = false
		h, _, _, _ := n.match(pos, at("header"), false)
		b, _, _, _ := n.match(pos, at("body"), false)
		s := "(" + h + " || " + b + ")"
		if t.negated {
			s = "!" + s
		}
		return s, Approximate, fmt.Sprintf("%s is searched in the headers and the body, not in a banner", describe(t)), true
	}
	if t.op == "exists" || t.op == "null" {
		return no("exists is not converted for nuclei")
	}
	if t.hex {
		return no("hex values are not converted for nuclei")
	}
	if probe != "default" && strings.HasPrefix(t.field, "tls.") {
		return no("certificate fields of a custom probe are not converted for nuclei")
	}
	switch f := t.field; {
	case f == "http.title":
		return n.match(t, at("title"), false)
	case f == "http.body":
		return n.match(t, at("body"), false)
	case f == "http.headers_raw":
		s, fid, note, ok := n.match(t, at("header"), false)
		if ok && (t.cased || strings.ContainsAny(t.value, ":\r\n")) {
			fid, note = Approximate, "nuclei rebuilds the header block: headers sorted, names in canonical case, one space after the colon"
		}
		return s, fid, note, ok
	case strings.HasPrefix(f, fields.HeaderPrefix):
		name := strings.TrimPrefix(f, fields.HeaderPrefix)
		if !nucleiHeaderRe.MatchString(name) {
			return no("nuclei has no variable for this header name")
		}
		return n.match(t, at("h:"+strings.ReplaceAll(name, "-", "_")), false)
	case f == "http.status_code":
		return n.number(t, at("status_code"))
	case f == "http.body.mmh3":
		return n.hash(t, "mmh3("+at("body")+")", Exact, "")
	case f == "http.body.sha256":
		return n.hash(t, "sha256("+at("body")+")", Exact, "")
	case strings.HasPrefix(f, "http.favicon."):
		if probe != "default" {
			return no("favicons of a custom probe are not converted for nuclei")
		}
		body := ref(faviconReq + "/body")
		var fn string
		switch f {
		case "http.favicon.mmh3":
			fn = "mmh3(base64_py(" + body + "))"
		case "http.favicon.md5":
			fn = "md5(" + body + ")"
		case "http.favicon.sha256":
			fn = "sha256(" + body + ")"
		default:
			return no("unknown favicon hash")
		}
		pos := t
		pos.negated = false
		s, fid, note, ok := n.hash(pos, fn, Approximate, nucleiFaviconNote)
		if !ok {
			return s, fid, note, ok
		}
		// The scanner only hashes a favicon it got with status 200.
		s = "(" + ref(faviconReq+"/status_code") + " == 200 && " + s + ")"
		if t.negated {
			s = "!" + s
		}
		return s, fid, note, ok
	case f == "tls.cert.subject.cn":
		return n.match(t, ref("ssl/subject_cn"), false)
	case f == "tls.cert.issuer.cn":
		return n.match(t, ref("ssl/issuer_cn"), false)
	case f == "tls.cert.subject.o", f == "tls.cert.issuer.o":
		// Nuclei prints the list as [a b]; one organisation, the usual case,
		// comes out as itself.
		v := map[string]string{"tls.cert.subject.o": "subject_org", "tls.cert.issuer.o": "issuer_org"}[f]
		s, _, _, ok := n.match(t, unbracket(ref("ssl/"+v)), false)
		return s, Approximate, "nuclei joins several organisations with spaces", ok
	case f == "tls.cert.san":
		// DNS names have no spaces, so one per line, matched with (?m).
		// The separator must be a real newline: the DSL reads \n as n.
		s, _, _, ok := n.match(t, "replace("+unbracket(ref("ssl/subject_an"))+", \" \", \"\n\")", true)
		return s, Approximate, "nuclei's subject_an lists DNS names only, not IP addresses", ok
	case f == "tls.cert.sha256", f == "tls.cert.sha1":
		if t.op != "eq" || t.wild {
			return no("only equality is converted for certificate hashes")
		}
		s := "contains(to_string(" + ref("ssl/fingerprint_hash") + "), " + dslQuote(strings.ToLower(t.value)) + ")"
		if t.negated {
			s = "!" + s
		}
		return s, Exact, "", true
	}
	return no("no nuclei equivalent")
}

// unbracket turns a list that Nuclei prints as [a b] into "a b".
func unbracket(x string) string {
	return `trim_suffix(trim_prefix(to_string(` + x + `), "["), "]")`
}

// match renders a string comparison. list marks one element per line, where
// equality, prefix and suffix apply to a line.
func (n *nuclei) match(t term, x string, list bool) (string, Fidelity, string, bool) {
	not := ""
	if t.negated {
		not = "!"
	}
	if t.op == "re" {
		if list {
			return not + "regex(" + dslQuote("(?m)"+t.value) + ", " + x + ")", Exact, "", true
		}
		return not + "regex(" + dslQuote(t.value) + ", " + x + ")", Exact, "", true
	}
	if t.wild || list {
		pat := wildcardRegexp(t.raw, t.wild)
		switch {
		case t.op == "eq":
			pat = "^" + pat + "$"
		case t.op == "startswith":
			pat = "^" + pat
		case t.op == "endswith":
			pat = pat + "$"
		case t.op != "contains":
			return "", 0, fmt.Sprintf("%s: %s is not converted for nuclei", describe(t), t.op), false
		}
		flags := "(?is)"
		switch {
		case list && t.cased:
			flags = "(?m)"
		case list:
			flags = "(?mi)"
		case t.cased:
			flags = "(?s)"
		}
		return not + "regex(" + dslQuote(flags+pat) + ", " + x + ")", Exact, "", true
	}
	v := t.value
	if !t.cased {
		x, v = "tolower("+x+")", strings.ToLower(v)
	}
	switch t.op {
	case "eq":
		if t.negated {
			return x + " != " + dslQuote(v), Exact, "", true
		}
		return x + " == " + dslQuote(v), Exact, "", true
	case "contains":
		return not + "contains(" + x + ", " + dslQuote(v) + ")", Exact, "", true
	case "startswith":
		return not + "starts_with(" + x + ", " + dslQuote(v) + ")", Exact, "", true
	case "endswith":
		return not + "ends_with(" + x + ", " + dslQuote(v) + ")", Exact, "", true
	}
	return "", 0, fmt.Sprintf("%s: %s is not converted for nuclei", describe(t), t.op), false
}

func (n *nuclei) number(t term, x string) (string, Fidelity, string, bool) {
	if _, err := strconv.ParseFloat(t.value, 64); err != nil || t.wild {
		return "", 0, fmt.Sprintf("%s: not a number", describe(t)), false
	}
	op := map[string]string{"eq": "==", "gt": ">", "gte": ">=", "lt": "<", "lte": "<="}[t.op]
	if op == "" {
		return "", 0, fmt.Sprintf("%s: %s is not converted for nuclei", describe(t), t.op), false
	}
	s := x + " " + op + " " + t.value
	if t.negated {
		s = "!(" + s + ")"
	}
	return s, Exact, "", true
}

func (n *nuclei) hash(t term, x string, f Fidelity, note string) (string, Fidelity, string, bool) {
	if t.op != "eq" || t.wild {
		return "", 0, fmt.Sprintf("%s: only equality is converted for hashes", describe(t)), false
	}
	s := x + " == " + dslQuote(strings.ToLower(t.value))
	if t.negated {
		s = x + " != " + dslQuote(strings.ToLower(t.value))
	}
	return s, f, note, true
}

// dslQuote writes a string literal for Nuclei's DSL, which reads a
// backslash as an escape for the next character.
func dslQuote(s string) string {
	return `"` + strings.NewReplacer(`\`, `\\`, `"`, `\"`).Replace(s) + `"`
}

// wildcardRegexp turns a Sigma value into an RE2 pattern, as the evaluator
// does: * and ? are wildcards when wild is set, \*, \? and \\ literals.
func wildcardRegexp(s string, wild bool) string {
	if !wild {
		lit, _ := unwildcard(s)
		return regexp.QuoteMeta(lit)
	}
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c == '\\' && i+1 < len(s) && (s[i+1] == '*' || s[i+1] == '?' || s[i+1] == '\\'):
			b.WriteString(regexp.QuoteMeta(s[i+1 : i+2]))
			i++
		case c == '*':
			b.WriteString(".*")
		case c == '?':
			b.WriteString(".")
		default:
			b.WriteString(regexp.QuoteMeta(s[i : i+1]))
		}
	}
	return b.String()
}

// titleDSL computes http.title as the scanner does: the first <title>,
// entities decoded, whitespace collapsed and trimmed. "" if there is none.
func titleDSL(body string) string {
	return `regex("(?is)<title[^>]*>.*?</title>", ` + body + `) ? trim_space(replace_regex(html_unescape(replace_regex(` + body +
		`, "(?is)^.*?<title[^>]*>(.*?)</title>.*$", "$1")), "[\\t\\n\\v\\f\\r \\x{85}\\x{A0}\\p{Z}]+", " ")) : ""`
}

// ---- template ----

type nucleiTemplate struct {
	ID        string            `yaml:"id"`
	Info      nucleiInfo        `yaml:"info"`
	Variables map[string]string `yaml:"variables,omitempty"`
	SSL       []nucleiSSL       `yaml:"ssl,omitempty"`
	HTTP      []nucleiHTTP      `yaml:"http,omitempty"`
}

type nucleiInfo struct {
	Name           string                `yaml:"name"`
	Author         string                `yaml:"author"`
	Severity       string                `yaml:"severity"`
	Description    string                `yaml:"description,omitempty"`
	Reference      []string              `yaml:"reference,omitempty"`
	Classification *nucleiClassification `yaml:"classification,omitempty"`
	Metadata       map[string]any        `yaml:"metadata,omitempty"`
	Tags           string                `yaml:"tags,omitempty"`
}

type nucleiClassification struct {
	CPE string `yaml:"cpe"`
}

type nucleiSSL struct {
	Address  string          `yaml:"address"`
	Matchers []nucleiMatcher `yaml:"matchers,omitempty"`
}

type nucleiHTTP struct {
	Method           string            `yaml:"method,omitempty"`
	Path             []string          `yaml:"path,omitempty"`
	Raw              []string          `yaml:"raw,omitempty"`
	ReqCondition     bool              `yaml:"req-condition,omitempty"`
	StopAtFirstMatch bool              `yaml:"stop-at-first-match,omitempty"`
	Matchers         []nucleiMatcher   `yaml:"matchers"`
	Extractors       []nucleiExtractor `yaml:"extractors,omitempty"`
}

type nucleiMatcher struct {
	Type string   `yaml:"type"`
	DSL  []string `yaml:"dsl"`
}

type nucleiExtractor struct {
	Type     string   `yaml:"type"`
	Name     string   `yaml:"name"`
	Internal bool     `yaml:"internal,omitempty"`
	Part     string   `yaml:"part,omitempty"`
	Group    int      `yaml:"group,omitempty"`
	Regex    []string `yaml:"regex,omitempty"`
	JSON     []string `yaml:"json,omitempty"`
	DSL      []string `yaml:"dsl,omitempty"`
}

type nucleiRequest struct {
	probe   string // "default", "favicon" or a custom probe id
	method  string
	path    string
	headers map[string]string
}

var nucleiIDRe = regexp.MustCompile(`[^a-z0-9]+`)

// NucleiID is the template id for a rule: athar- and the rule's file name.
func NucleiID(r *rule.Rule) string {
	base := strings.TrimSuffix(filepath.Base(r.Path), filepath.Ext(r.Path))
	s := strings.Trim(nucleiIDRe.ReplaceAllString(strings.ToLower(base), "-"), "-")
	if s == "" {
		s = strings.Trim(nucleiIDRe.ReplaceAllString(strings.ToLower(r.ID), "-"), "-")
	}
	return "athar-" + s
}

func convertNuclei(r *rule.Rule) (Result, error) {
	e, err := build(r)
	if err != nil {
		return Result{}, err
	}
	n := &nuclei{r: r}
	c := &converter{b: n, engine: nucleiTarget}
	out := c.lower(nnf(e, false))
	res := Result{Engine: nucleiTarget, Fidelity: c.fid, Notes: dedup(c.notes)}
	if x, ok := out.(boolExpr); ok {
		res.Fidelity = Unsupported
		if bool(x) {
			res.Notes = append(res.Notes, "nothing convertible is left; the template would match everything")
		} else {
			res.Notes = append(res.Notes, "the condition can never match")
		}
		return res, nil
	}
	expr := c.render(out, false)

	// What the expression reads decides the requests: the favicon, custom
	// probes by id, the baseline, and the ssl block.
	used := map[string]bool{}
	for _, m := range refRe.FindAllStringSubmatch(expr, -1) {
		where, _, _ := strings.Cut(m[1], "/")
		used[where] = true
	}
	var reqs []nucleiRequest
	if used[faviconReq] {
		reqs = append(reqs, nucleiRequest{probe: faviconReq, method: "GET", path: "/favicon.ico"})
	}
	var ids []string
	for id := range used {
		if id != "default" && id != faviconReq && id != "ssl" {
			ids = append(ids, id)
		}
	}
	sort.Strings(ids)
	for _, id := range ids {
		q := n.r.Probes[id].Request
		m := strings.ToUpper(q.Method)
		if m == "" {
			m = "GET"
		}
		p := q.Path
		if p == "" {
			p = "/"
		}
		reqs = append(reqs, nucleiRequest{probe: id, method: m, path: p, headers: q.Headers})
	}
	// The baseline goes last: Nuclei reports the last request's URL.
	if used["default"] {
		reqs = append(reqs, nucleiRequest{probe: "default", method: "GET", path: "/"})
	}
	multi := len(reqs) > 1
	httpBlock := len(reqs) > 0
	if !httpBlock && r.Target.TLS == "none" {
		res.Fidelity = Unsupported
		res.Notes = append(res.Notes, "target.tls is none, but the rule only reads the certificate, which nuclei gets over TLS")
		return res, nil
	}
	index := map[string]int{}
	for i, q := range reqs {
		index[q.probe] = i + 1
	}

	// Resolve references.
	vars := map[string]string{}
	titles := map[int]bool{}
	expr = refRe.ReplaceAllStringFunc(expr, func(m string) string {
		name := m[1 : len(m)-1]
		where, field, _ := strings.Cut(name, "/")
		if where == "ssl" {
			if !httpBlock {
				return field
			}
			vars["ssl_"+field] = ""
			return "ssl_" + field
		}
		i := index[where]
		suffix := ""
		if multi {
			suffix = "_" + strconv.Itoa(i)
		}
		switch {
		case field == "title":
			titles[i] = true
			vars["title"+suffix] = ""
			return "title" + suffix
		case strings.HasPrefix(field, "h:"):
			v := strings.TrimPrefix(field, "h:") + suffix
			vars[v] = ""
			return v
		}
		return field + suffix
	})
	if multi {
		expr = "status_code_" + strconv.Itoa(len(reqs)) + " > 0 && (" + expr + ")"
	}
	// target.tls: the matcher only holds for the scheme the request used. An
	// ssl block on its own matches only over TLS and needs no guard.
	if scheme := map[string]string{"required": "https", "none": "http"}[r.Target.TLS]; scheme != "" && httpBlock {
		if !multi {
			expr = "(" + expr + ")"
		}
		expr = "Scheme == " + dslQuote(scheme) + " && " + expr
	}

	t := nucleiTemplate{ID: NucleiID(r), Info: nucleiInfoFor(r, len(reqs), httpBlock)}
	if len(vars) > 0 {
		t.Variables = vars
	}
	matcher := []nucleiMatcher{{Type: "dsl", DSL: []string{expr}}}
	if used["ssl"] {
		s := nucleiSSL{Address: "{{Host}}:{{Port}}"}
		if !httpBlock {
			s.Matchers = matcher
		}
		t.SSL = []nucleiSSL{s}
	}
	if httpBlock {
		h := nucleiHTTP{Matchers: matcher}
		raw := false
		for _, q := range reqs {
			raw = raw || q.method != "GET" || len(q.headers) > 0
		}
		for _, q := range reqs {
			if raw {
				h.Raw = append(h.Raw, rawRequest(q))
			} else {
				h.Path = append(h.Path, "{{RootURL}}"+q.path)
			}
		}
		if !raw {
			h.Method = "GET"
		}
		if multi {
			h.ReqCondition, h.StopAtFirstMatch = true, true
		}
		var idx []int
		for i := range titles {
			idx = append(idx, i)
		}
		sort.Ints(idx)
		for _, i := range idx {
			suffix, body := "", "body"
			if multi {
				suffix, body = "_"+strconv.Itoa(i), "body_"+strconv.Itoa(i)
			}
			h.Extractors = append(h.Extractors, nucleiExtractor{Type: "dsl", Name: "title" + suffix, Internal: true, DSL: []string{titleDSL(body)}})
		}
		x, notes := nucleiExtractors(r, multi, index, titles, &h)
		h.Extractors = append(h.Extractors, x...)
		res.Notes = append(res.Notes, notes...)
		t.HTTP = []nucleiHTTP{h}
	}
	if len(ids) > 0 {
		plural := ""
		if len(ids) > 1 {
			plural = "s"
		}
		res.Notes = append(res.Notes, fmt.Sprintf("sends %d custom probe request%s; athar scan sends custom probes only with -probes", len(ids), plural))
	}
	t.Info.Metadata["athar-fidelity"] = res.Fidelity.String()

	var body strings.Builder
	enc := yaml.NewEncoder(&body)
	enc.SetIndent(2)
	if err := enc.Encode(t); err != nil {
		return Result{}, err
	}
	enc.Close()
	var head strings.Builder
	fmt.Fprintf(&head, "# Converted by athar convert from %s", filepath.ToSlash(r.Path))
	if r.ID != "" {
		fmt.Fprintf(&head, " (Athar rule %s)", r.ID)
	}
	head.WriteString(".\n")
	if r.Author != "" {
		fmt.Fprintf(&head, "# Rule by %s, licensed under the Detection Rule License 1.1:\n# %s\n", r.Author, DRLURL)
	}
	fmt.Fprintf(&head, "# Fidelity: %s\n", res.Fidelity)
	for _, note := range res.Notes {
		fmt.Fprintf(&head, "# Note: %s\n", note)
	}
	res.TemplateID = t.ID
	res.Template = head.String() + body.String()
	return res, nil
}

func rawRequest(q nucleiRequest) string {
	var b strings.Builder
	fmt.Fprintf(&b, "%s %s HTTP/1.1\nHost: {{Hostname}}\n", q.method, q.path)
	names := make([]string, 0, len(q.headers))
	for k := range q.headers {
		names = append(names, k)
	}
	sort.Strings(names)
	for _, k := range names {
		fmt.Fprintf(&b, "%s: %s\n", k, q.headers[k])
	}
	b.WriteString("\n")
	return b.String()
}

func nucleiInfoFor(r *rule.Rule, requests int, http bool) nucleiInfo {
	info := nucleiInfo{
		Name:        r.Title,
		Author:      r.Author,
		Severity:    "info",
		Description: strings.TrimSpace(r.Description),
		Reference:   r.References,
		Metadata:    map[string]any{},
	}
	if r.ID != "" {
		info.Metadata["athar-id"] = r.ID
	}
	if info.Author == "" {
		info.Author = "unknown"
	}
	if r.Identifies.CPE != "" {
		info.Classification = &nucleiClassification{CPE: r.Identifies.CPE}
	}
	if http {
		info.Metadata["max-request"] = requests
	}
	for k, v := range map[string]string{
		"vendor": r.Identifies.Vendor, "product": r.Identifies.Product,
		"athar-family": r.Identifies.Family, "athar-confidence": r.Confidence,
	} {
		if v != "" {
			info.Metadata[k] = v
		}
	}
	if r.Author != "" {
		info.Metadata["license"] = "DRL-1.1"
	}
	for _, engine := range Engines {
		if q, err := Convert(r, engine); err == nil && q.Fidelity != Unsupported {
			info.Metadata[engine+"-query"] = q.Query
		}
	}
	tags := []string{"tech", "athar"}
	if c := r.Identifies.Category; c != "" {
		tags = append(tags, c)
	}
	info.Tags = strings.Join(tags, ",")
	return info
}

// nucleiExtractors converts the rule's extract entries. They read the
// baseline response.
func nucleiExtractors(r *rule.Rule, multi bool, index map[string]int, titles map[int]bool, h *nucleiHTTP) ([]nucleiExtractor, []string) {
	var names []string
	for k := range r.Extract {
		names = append(names, k)
	}
	sort.Strings(names)
	var out []nucleiExtractor
	var notes []string
	i, ok := index["default"]
	if !ok {
		for _, name := range names {
			notes = append(notes, fmt.Sprintf("extract %s reads the baseline response, which the template does not request", name))
		}
		return nil, notes
	}
	suffix := ""
	if multi {
		suffix = "_" + strconv.Itoa(i)
	}
	for _, name := range names {
		x := r.Extract[name]
		var part string
		switch f := x.Field; {
		case f == "http.title":
			part = "title" + suffix
			if !titles[i] {
				titles[i] = true
				body := "body"
				if multi {
					body = "body_" + strconv.Itoa(i)
				}
				h.Extractors = append(h.Extractors, nucleiExtractor{Type: "dsl", Name: part, Internal: true, DSL: []string{titleDSL(body)}})
			}
		case f == "http.body":
			part = "body" + suffix
		case f == "http.headers_raw":
			part = "header" + suffix
		case strings.HasPrefix(f, fields.HeaderPrefix) && nucleiHeaderRe.MatchString(strings.TrimPrefix(f, fields.HeaderPrefix)):
			part = strings.ReplaceAll(strings.TrimPrefix(f, fields.HeaderPrefix), "-", "_") + suffix
		default:
			notes = append(notes, fmt.Sprintf("extract %s reads %s, which is not converted for nuclei", name, f))
			continue
		}
		e := nucleiExtractor{Name: name, Part: part}
		switch {
		case x.Regex != "":
			re, err := regexp.Compile(x.Regex)
			if err != nil {
				continue
			}
			e.Type, e.Regex = "regex", []string{x.Regex}
			e.Group = re.SubexpIndex(name)
			if e.Group < 0 {
				e.Group = min(1, re.NumSubexp())
			}
		case x.JSONPath != "":
			e.Type, e.JSON = "json", []string{strings.TrimPrefix(x.JSONPath, "$")}
		default:
			continue
		}
		out = append(out, e)
	}
	return out, notes
}
