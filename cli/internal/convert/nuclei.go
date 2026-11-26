package convert

import (
	"encoding/hex"
	"fmt"
	"path/filepath"
	"regexp"
	"regexp/syntax"
	"sort"
	"strconv"
	"strings"
	"sync"
	"unicode"

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
//   - http.headers.<name>: read from the header block, one value per line.
//   - certificate fields: an ssl block runs before the http block, whose
//     matcher reads them as ssl_*.
//   - favicon hashes: a second request to /favicon.ico.
//   - custom HTTP probes: one more request each.
//
// Several requests run with req-condition, so the matcher can read body_2
// and the like, and it is guarded by the last request's status, so it is
// only evaluated once every response is in.
//
// A response may lack a field, and Nuclei refuses to evaluate an expression
// with an undefined name, so the matcher never reads a name that may be
// undefined. Defaults under variables don't help: Nuclei clusters templates
// that send the same request and evaluates all of them with the variables
// of the first one. Only a template with an ssl and an http block gives its
// ssl_* names defaults that way, because Nuclei does not cluster a template
// with two protocols.
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

// faviconReq names the favicon request.
const faviconReq = "#favicon"

// probeRef names a custom probe's request in references. Probe ids are free
// text; in hex, none is taken for "default", faviconReq or "ssl", none holds
// the characters that delimit a reference, and no two share a name.
func probeRef(id string) string { return "probe:" + hex.EncodeToString([]byte(id)) }

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
	marked := nucleiMarked(p.Request.Method) || nucleiMarked(p.Request.Path)
	for k, v := range p.Request.Headers {
		marked = marked || nucleiMarked(k) || nucleiMarked(v)
	}
	if marked {
		return "", 0, fmt.Sprintf("%s: nuclei would expand the {{ or § in the request of the custom probe %q", describe(t), t.probe), false
	}
	return n.render(t, probeRef(t.probe))
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
	exists := t.op == "exists" || t.op == "null"
	if exists && !nucleiOptional(t.field) {
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
		// The extractor puts = before the title, see titleDSL.
		return n.optional(t, hasTitle(at("body")), "trim_prefix("+at("title")+`, "=")`, false, false)
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
		s, fid, note, ok := n.header(t, name, at)
		if ok && name == "transfer-encoding" {
			fid, note = Approximate, "nuclei's header block has Transfer-Encoding; the scanner's HTTP parser takes it out of the headers"
		}
		return s, fid, note, ok
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
		// The scanner only hashes a favicon it got with status 200, and an
		// empty answer is no favicon.
		status := ref(faviconReq+"/status_code") + " == 200"
		filled := "len(" + body + ") > 0"
		if exists {
			s, _, _, ok := n.optional(t, "("+status+" && "+filled+")", "", false, false)
			return s, Approximate, nucleiFaviconNote, ok
		}
		pos := t
		pos.negated = false
		s, fid, note, ok := n.hash(pos, fn, Approximate, nucleiFaviconNote)
		if !ok {
			return s, fid, note, ok
		}
		if strings.ToLower(t.value) == nucleiEmptyFavicon[f] {
			s = filled + " && " + s
		}
		s = "(" + status + " && " + s + ")"
		if t.negated {
			s = "!" + s
		}
		return s, fid, note, ok
	case f == "tls.cert.subject.cn":
		return n.optional(t, ref("ssl?/subject_cn"), ref("ssl/subject_cn"), false, true)
	case f == "tls.cert.issuer.cn":
		return n.optional(t, ref("ssl?/issuer_cn"), ref("ssl/issuer_cn"), false, true)
	case f == "tls.cert.subject.o", f == "tls.cert.issuer.o":
		// Nuclei prints the list as [a b]; one organisation, the usual case,
		// comes out as itself.
		v := map[string]string{"tls.cert.subject.o": "subject_org", "tls.cert.issuer.o": "issuer_org"}[f]
		s, fid, note, ok := n.optional(t, ref("ssl?/"+v), unbracket(ref("ssl/"+v)), false, true)
		if exists {
			return s, fid, note, ok
		}
		return s, Approximate, "nuclei joins several organisations with spaces", ok
	case f == "tls.cert.san":
		// DNS names have no spaces, so one per line, matched with (?m).
		// The separator must be a real newline: the DSL reads \n as n.
		s, _, _, ok := n.optional(t, ref("ssl?/subject_an"), "replace("+unbracket(ref("ssl/subject_an"))+", \" \", \"\n\")", true, true)
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

// nucleiOptional reports whether a response may lack the field in a way the
// template can tell; exists is converted for these fields.
func nucleiOptional(field string) bool {
	switch field {
	case "http.title", "tls.cert.subject.cn", "tls.cert.issuer.cn", "tls.cert.subject.o", "tls.cert.issuer.o", "tls.cert.san":
		return true
	}
	return strings.HasPrefix(field, fields.HeaderPrefix) || strings.HasPrefix(field, "http.favicon.")
}

// nucleiEmptyFavicon is what the template's hash functions give for an empty
// file; base64_py("") is a line break.
var nucleiEmptyFavicon = map[string]string{
	"http.favicon.mmh3":   "-1840324437",
	"http.favicon.md5":    "d41d8cd98f00b204e9800998ecf8427e",
	"http.favicon.sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
}

// optional renders a condition on a field that a response may lack. In the
// scanner an absent field fails every comparison, so a negated comparison
// holds, and exists tells present from absent. has is the DSL test for the
// field and x reads its value. Where x is "" without the field, the test is
// only written if the comparison holds for "". guard is set where x can't be
// read without the field: && skips its right side, so has guards x.
func (n *nuclei) optional(t term, has, x string, list, guard bool) (string, Fidelity, string, bool) {
	if t.op == "exists" || t.op == "null" {
		if (t.op == "exists" && t.value == "true") != t.negated {
			return has, Exact, "", true
		}
		return "!(" + has + ")", Exact, "", true
	}
	if !guard && !matchesEmpty(t) {
		return n.match(t, x, list)
	}
	pos := t
	pos.negated = false
	s, fid, note, ok := n.match(pos, x, list)
	if !ok {
		return s, fid, note, ok
	}
	s = "(" + has + " && " + s + ")"
	if t.negated {
		s = "!" + s
	}
	return s, fid, note, true
}

// matchesEmpty reports whether a string comparison holds for "".
func matchesEmpty(t term) bool {
	pat := t.value
	if t.op != "re" {
		pat = wildcardRegexp(t.raw, t.wild)
		switch t.op {
		case "eq":
			pat = "^" + pat + "$"
		case "startswith":
			pat = "^" + pat
		case "endswith":
			pat = pat + "$"
		}
		pat = "(?s)" + pat
	}
	re, err := regexp.Compile(pat)
	return err != nil || re.MatchString("")
}

// header renders a condition on a header's values. Nuclei's variable for a
// header joins repeated headers with a space and is undefined without the
// header, so the condition is a regular expression on the header block,
// where every value has its own "Name: value" line. As in the scanner, it
// holds if one value matches and fails without the header.
func (n *nuclei) header(t term, name string, at func(string) string) (string, Fidelity, string, bool) {
	block := at("header")
	has := "regex(" + dslQuote("(?mi)^"+name+":") + ", " + block + ")"
	if t.op == "exists" || t.op == "null" {
		return n.optional(t, has, "", false, false)
	}
	not := ""
	if t.negated {
		not = "!"
	}
	pat, why := headerRegexp(t, name)
	switch {
	case pat == "" && t.op == "re":
		// && skips its right side, so the variable is only read if set.
		pos := t
		pos.negated = false
		s, _, _, _ := n.match(pos, at("h:"+strings.ReplaceAll(name, "-", "_")), false)
		return not + "(" + has + " && " + s + ")", Approximate,
			fmt.Sprintf("%s is matched against the header's values joined with spaces, not against each value", describe(t)), true
	case pat == "":
		return "", 0, fmt.Sprintf("%s: %s", describe(t), why), false
	}
	return not + "regex(" + dslQuote(pat) + ", " + block + ")", Exact, "", true
}

// headerRegexp is the regular expression that finds, in a header block with
// CRLF line ends, a line of the header name whose value satisfies t. It is
// "" with a reason if there is none.
func headerRegexp(t term, name string) (pat, why string) {
	// The name in any case; the value as the comparison says.
	line := "(?m)^(?i:" + name + "): "
	var v string
	switch t.op {
	case "re":
		var ok bool
		if v, ok = lineRegexp(t.value); !ok {
			return "", "the expression can't be confined to one value"
		}
	case "eq", "contains", "startswith", "endswith":
		if strings.ContainsAny(t.value, "\r\n") {
			return "", "a header value has no line break"
		}
		v = wildcardRegexp(t.raw, t.wild)
		if t.wild {
			v = lineWildcards(v)
		}
		if t.op == "contains" || t.op == "endswith" {
			v = ".*" + v
		}
		if t.op == "eq" || t.op == "endswith" {
			v += `\r?$`
		}
		if !t.cased {
			line = "(?mi)^" + name + ": "
		}
	default:
		return "", t.op + " is not converted for nuclei"
	}
	return line + v, ""
}

// lineWildcards keeps the wildcards of a pattern from wildcardRegexp inside
// one line.
func lineWildcards(pat string) string {
	var b strings.Builder
	for i := 0; i < len(pat); i++ {
		switch {
		case pat[i] == '\\' && i+1 < len(pat):
			b.WriteString(pat[i : i+2])
			i++
		case pat[i] == '.':
			b.WriteString(`[^\r\n]`)
		default:
			b.WriteByte(pat[i])
		}
	}
	return b.String()
}

// lineRegexp rewrites a rule's regular expression so that it matches a value
// inside its line of the header block as it matches the value alone: nothing
// in it matches a line break, and ^ and $ become the ends of the value. They
// may only stand at the ends of the expression or of its top-level
// alternatives; ok is false for an expression that can't be rewritten.
func lineRegexp(src string) (pat string, ok bool) {
	re, err := syntax.Parse(src, syntax.Perl)
	if err != nil {
		return "", false
	}
	alts := []*syntax.Regexp{re}
	if re.Op == syntax.OpAlternate {
		alts = re.Sub
	}
	out := make([]string, len(alts))
	for i, a := range alts {
		subs := []*syntax.Regexp{a}
		if a.Op == syntax.OpConcat {
			subs = a.Sub
		}
		lead, tail := ".*?", ""
		if len(subs) > 0 && (subs[0].Op == syntax.OpBeginText || subs[0].Op == syntax.OpBeginLine) {
			lead, subs = "", subs[1:]
		}
		if k := len(subs) - 1; k >= 0 && (subs[k].Op == syntax.OpEndText || subs[k].Op == syntax.OpEndLine) {
			tail, subs = `\r?$`, subs[:k]
		}
		body := ""
		for _, s := range subs {
			if !confine(s) {
				return "", false
			}
		}
		if len(subs) > 0 {
			body = (&syntax.Regexp{Op: syntax.OpConcat, Sub: subs}).String()
		}
		out[i] = lead + "(?:" + body + ")" + tail
	}
	return "(?:" + strings.Join(out, "|") + ")", true
}

// confine takes line breaks out of everything re can match. It returns false
// if re has an anchor or a literal line break.
func confine(re *syntax.Regexp) bool {
	switch re.Op {
	case syntax.OpBeginText, syntax.OpEndText, syntax.OpBeginLine, syntax.OpEndLine:
		return false
	case syntax.OpLiteral:
		if strings.ContainsAny(string(re.Rune), "\r\n") {
			return false
		}
	case syntax.OpAnyChar, syntax.OpAnyCharNotNL:
		re.Op, re.Rune = syntax.OpCharClass, []rune{0, unicode.MaxRune}
		fallthrough
	case syntax.OpCharClass:
		var class []rune
		for i := 0; i+1 < len(re.Rune); i += 2 {
			lo, hi := re.Rune[i], re.Rune[i+1]
			for _, c := range "\n\r" {
				if lo <= c && c <= hi {
					if lo < c {
						class = append(class, lo, c-1)
					}
					lo = c + 1
				}
			}
			if lo <= hi {
				class = append(class, lo, hi)
			}
		}
		re.Rune = class
		if len(class) == 0 {
			re.Op = syntax.OpNoMatch
		}
	}
	for _, s := range re.Sub {
		if !confine(s) {
			return false
		}
	}
	return true
}

// lowered maps a letter to the other letters that tolower() turns into it.
var lowered = sync.OnceValue(func() map[rune][]rune {
	m := map[rune][]rune{}
	for _, cr := range unicode.CaseRanges {
		for r := rune(cr.Lo); r <= rune(cr.Hi); r++ {
			if l := unicode.ToLower(r); l != r {
				m[l] = append(m[l], r)
			}
		}
	}
	return m
})

// foldsAsLower reports whether comparing lowercased strings finds s in the
// same texts as the scanner's (?i) does. (?i) folds case as Unicode's simple
// case folding does, which is not lowercasing: a long s folds to s and a
// final sigma to σ, but both are lowercase already, and a dotted capital I
// becomes i in lowercase without folding to it. So for every letter of s,
// the letters with the same lowercase must be the letters (?i) takes for it.
// Of the ASCII letters, i and s fail that.
func foldsAsLower(s string) bool {
	for _, r := range s {
		l := unicode.ToLower(r)
		same := len(lowered()[l])
		if unicode.ToLower(l) == l {
			same++
		}
		folds := 1
		for f := unicode.SimpleFold(r); f != r; f = unicode.SimpleFold(f) {
			if unicode.ToLower(f) != l {
				return false
			}
			folds++
		}
		if folds != same {
			return false
		}
	}
	return true
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
	// tolower() is only used where it folds case as the scanner does.
	if t.wild || list || (!t.cased && !foldsAsLower(t.value)) {
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
// backslash as an escape for the next character. Nuclei expands {{…}} in an
// expression before it evaluates it, so the second of two opening braces
// gets a backslash: the literal reads the same and holds no marker.
func dslQuote(s string) string {
	s = strings.NewReplacer(`\`, `\\`, `"`, `\"`).Replace(s)
	for nucleiBracesRe.MatchString(s) {
		s = nucleiBracesRe.ReplaceAllString(s, `${1}\${2}`)
	}
	return `"` + s + `"`
}

// nucleiBracesRe finds what Nuclei takes for the start of {{…}}: two opening
// braces, each as it is or percent-encoded. Nuclei's own pattern, %7[B|b],
// takes %7| too.
var nucleiBracesRe = regexp.MustCompile(`(\{|%7[Bb|])(\{|%7[Bb|])`)

// nucleiMarked reports whether Nuclei would expand a part of s in a request:
// it replaces {{name}} and §name§, evaluates {{expression}}, and sends no
// request in which a {{…}} is left.
func nucleiMarked(s string) bool {
	return nucleiBracesRe.MatchString(s) || strings.Contains(s, "§")
}

// reBraces writes the first brace of every {{ in an RE2 pattern as \x7B.
// Nuclei replaces {{randstr}} in a template's text before it reads the YAML,
// so quoting can't hide the braces; the pattern matches the same.
func reBraces(re string) string {
	var b strings.Builder
	quoted := false // inside \Q…\E, where nothing can be escaped
	for i := 0; i < len(re); i++ {
		rest := re[i:]
		switch {
		case quoted && strings.HasPrefix(rest, `\E`):
			quoted = false
			b.WriteString(`\E`)
			i++
		case quoted && strings.HasPrefix(rest, "{{"):
			b.WriteString(`{\E\Q`)
		case quoted:
			b.WriteByte(re[i])
		case strings.HasPrefix(rest, `\Q`):
			quoted = true
			b.WriteString(`\Q`)
			i++
		case strings.HasPrefix(rest, `\{{`):
			b.WriteString(`\x7B`)
			i++
		case rest[0] == '\\' && len(rest) > 1:
			b.WriteString(rest[:2])
			i++
		case strings.HasPrefix(rest, "{{"):
			b.WriteString(`\x7B`)
		default:
			b.WriteByte(re[i])
		}
	}
	return b.String()
}

// yamlComment makes s safe in a # comment. A line break would end the
// comment and leave the rest of s as YAML, and a YAML file can't hold other
// control characters.
func yamlComment(s string) string {
	return strings.TrimSpace(strings.Map(func(r rune) rune {
		if unicode.IsControl(r) || r == 0x2028 || r == 0x2029 { // line and paragraph separator
			return ' '
		}
		return r
	}, s))
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

// hasTitle is the DSL test for a <title> element.
func hasTitle(body string) string {
	return `regex("(?is)<title[^>]*>.*?</title>", ` + body + `)`
}

// titleDSL computes http.title as the scanner does: the first <title>,
// entities decoded, whitespace collapsed and trimmed. The result is = and
// the title, and just = if there is none: Nuclei drops an empty result,
// which would leave the name undefined.
func titleDSL(body string) string {
	return hasTitle(body) + ` ? "=" + trim_space(replace_regex(html_unescape(replace_regex(` + body +
		`, "(?is)^.*?<title[^>]*>(.*?)</title>.*$", "$1")), "[\\t\\n\\v\\f\\r \\x{85}\\x{A0}\\p{Z}]+", " ")) : "="`
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
	probe   string // "default", faviconReq or probeRef(id)
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
		used[strings.TrimSuffix(where, "?")] = true
	}
	var reqs []nucleiRequest
	if used[faviconReq] {
		reqs = append(reqs, nucleiRequest{probe: faviconReq, method: "GET", path: "/favicon.ico"})
	}
	var ids []string
	for id := range n.r.Probes {
		if used[probeRef(id)] {
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
		reqs = append(reqs, nucleiRequest{probe: probeRef(id), method: m, path: p, headers: q.Headers})
	}
	// The baseline goes last: Nuclei reports the last request's URL.
	if used["default"] {
		reqs = append(reqs, nucleiRequest{probe: "default", method: "GET", path: "/"})
	}
	multi := len(reqs) > 1
	httpBlock := len(reqs) > 0
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
		// ssl?/field is the test for a certificate field, ssl/field its
		// value. The ssl block leaves an empty field undefined but lists
		// every field it has in response, as JSON.
		if where == "ssl" || where == "ssl?" {
			name := field
			if httpBlock {
				name = "ssl_" + field
				vars[name] = ""
			}
			switch {
			case where == "ssl":
				return name
			case httpBlock:
				return "to_string(" + name + `) != ""`
			}
			return "contains(response, " + dslQuote(`"`+field+`":`) + ")"
		}
		i := index[where]
		suffix := ""
		if multi {
			suffix = "_" + strconv.Itoa(i)
		}
		switch {
		case field == "title":
			titles[i] = true
			return "title" + suffix
		case strings.HasPrefix(field, "h:"):
			return strings.TrimPrefix(field, "h:") + suffix
		}
		return field + suffix
	})
	if multi {
		expr = "status_code_" + strconv.Itoa(len(reqs)) + " > 0 && (" + expr + ")"
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
	fmt.Fprintf(&head, "# Converted by athar convert from %s", yamlComment(filepath.ToSlash(r.Path)))
	if r.ID != "" {
		fmt.Fprintf(&head, " (Athar rule %s)", yamlComment(r.ID))
	}
	head.WriteString(".\n")
	if r.Author != "" {
		fmt.Fprintf(&head, "# Rule by %s, licensed under the Detection Rule License 1.1:\n# %s\n", yamlComment(r.Author), DRLURL)
	}
	fmt.Fprintf(&head, "# Fidelity: %s\n", res.Fidelity)
	for _, note := range res.Notes {
		fmt.Fprintf(&head, "# Note: %s\n", yamlComment(note))
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
	plain := false
	for _, name := range names {
		x := r.Extract[name]
		var part string
		switch f := x.Field; {
		case f == "http.title":
			if !titles[i] {
				titles[i] = true
				body := "body"
				if multi {
					body = "body_" + strconv.Itoa(i)
				}
				h.Extractors = append(h.Extractors, nucleiExtractor{Type: "dsl", Name: "title" + suffix, Internal: true, DSL: []string{titleDSL(body)}})
			}
			// The title without the = that titleDSL puts before it.
			part = "title_text" + suffix
			if !plain {
				plain = true
				h.Extractors = append(h.Extractors, nucleiExtractor{Type: "dsl", Name: part, Internal: true, DSL: []string{"trim_prefix(title" + suffix + `, "=")`}})
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
			e.Type, e.Regex = "regex", []string{reBraces(x.Regex)}
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
