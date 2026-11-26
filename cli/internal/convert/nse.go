package convert

import (
	_ "embed"
	"encoding/hex"
	"fmt"
	"math"
	"path/filepath"
	"regexp"
	"regexp/syntax"
	"sort"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/Athar-HQ/Athar/cli/internal/eval"
	"github.com/Athar-HQ/Athar/cli/internal/fields"
	"github.com/Athar-HQ/Athar/cli/internal/probe"
	"github.com/Athar-HQ/Athar/cli/internal/rule"
)

// nseTarget is the name -t takes.
const nseTarget = "nse"

// NSEScript is athar.nse, the Nmap script that runs converted rules. It is
// the same for every rule; athar convert -o writes it next to the rules'
// data files.
//
//go:embed athar.nse
var NSEScript string

// NSERulesDir is the folder next to athar.nse that the script reads rule
// data files from by default.
const NSERulesDir = "athar-rules"

// nseFormat versions the data files. athar.nse skips other versions.
const nseFormat = 1

// nse turns a rule into a data file for athar.nse. The script does what
// athar scan does (same requests, same parsing, same field values), so the
// data only has to carry the rule's logic:
//
//   - the condition, after the superset rule, as nested {"and", ...} and
//     {"or", ...} tables over terms;
//   - literal values folded for case-insensitive comparison, with the fold
//     table the script applies to responses;
//   - regular expressions (re, wildcards, extract) compiled by Go's
//     regexp/syntax, which the script runs on a Pike VM, so they match
//     exactly as in Go;
//   - the custom probes and which parts of the baseline probe the rule
//     needs, worked out as athar scan does.
type nse struct {
	r       *rule.Rule
	fold    map[rune]rune // non-ASCII rune -> representative of its case-folding orbit
	progs   []string      // compiled regular expressions, as Lua tables
	progIdx map[string]int
}

func (n *nse) andOp() string        { return " and " }
func (n *nse) orOp() string         { return " or " }
func (n *nse) canOr() bool          { return true }
func (n *nse) wrap(q string) string { return q }

// nseField reports whether athar.nse collects a field. It collects what
// athar scan collects, except what Nmap's sockets don't expose: the
// negotiated TLS parameters, JARM and JA3S, and the certificate DN and
// self_signed, which need more of X.509 than the script parses.
func nseField(f string) bool {
	switch f {
	case "service.port", "service.transport", "service.protocol", "service.banner",
		"http.status_code", "http.title", "http.body", "http.body.mmh3", "http.body.sha256",
		"http.headers_raw", "http.favicon.mmh3", "http.favicon.md5", "http.favicon.sha256",
		"tls.cert.subject.cn", "tls.cert.subject.o", "tls.cert.issuer.cn", "tls.cert.issuer.o",
		"tls.cert.serial", "tls.cert.sha256", "tls.cert.sha1", "tls.cert.san", "ssh.banner":
		return true
	}
	return strings.HasPrefix(f, fields.HeaderPrefix)
}

func (n *nse) term(t term) (string, Fidelity, string, bool) { return n.render(t) }

// probeTerm handles conditions on a custom probe's response. athar scan
// sends HTTP and TCP probes that pass the safety checks; the script sends
// the same.
func (n *nse) probeTerm(t term) (string, Fidelity, string, bool) {
	p, ok := n.r.Probes[t.probe]
	if !ok || len(p.Unsafe()) > 0 {
		return "", 0, fmt.Sprintf("%s uses the probe %q, which is not sent", describe(t), t.probe), false
	}
	switch strings.ToLower(p.Protocol) {
	case "http", "tcp":
		return n.render(t)
	}
	return "", 0, fmt.Sprintf("%s uses the probe %q, whose protocol is not sent", describe(t), t.probe), false
}

func (n *nse) render(t term) (string, Fidelity, string, bool) {
	no := func(why string) (string, Fidelity, string, bool) {
		return "", 0, fmt.Sprintf("%s: %s", describe(t), why), false
	}
	var kv []string
	if t.probe != "default" {
		kv = append(kv, "p = "+luaString(t.probe))
	}
	if t.field == "" {
		kv = append(kv, "k = true") // keyword: banner, header block and body
	} else {
		if !nseField(t.field) {
			return no("athar.nse does not collect this field")
		}
		kv = append(kv, "f = "+luaString(t.field))
	}
	switch t.op {
	case "exists", "null":
		kv = append(kv, `m = "exists"`, "x = "+strconv.FormatBool(t.op == "exists" && t.value == "true"))
	case "gt", "gte", "lt", "lte":
		f, err := strconv.ParseFloat(t.value, 64)
		if err != nil || t.wild {
			return no("not a number")
		}
		kv = append(kv, `m = "num"`, "o = "+luaString(t.op), "x = "+luaNumber(f))
	case "re":
		i, err := n.regex(t.raw)
		if err != nil {
			return no(err.Error())
		}
		kv = append(kv, `m = "re"`, "r = "+strconv.Itoa(i))
	case "eq", "contains", "startswith", "endswith":
		switch {
		case t.hex:
			b, err := hex.DecodeString(strings.ReplaceAll(t.raw, " ", ""))
			if err != nil {
				return no("invalid hex value")
			}
			kv = append(kv, "m = "+luaString(t.op), "v = "+luaString(string(b)), "c = true")
		case t.wild || strings.ContainsRune(t.value, utf8.RuneError):
			// The same regular expression the evaluator builds.
			i, err := n.regex(valuePattern(t.raw, t.op, t.cased))
			if err != nil {
				return no(err.Error())
			}
			kv = append(kv, `m = "re"`, "r = "+strconv.Itoa(i))
		case t.cased:
			kv = append(kv, "m = "+luaString(t.op), "v = "+luaString(t.value), "c = true")
		default:
			kv = append(kv, "m = "+luaString(t.op), "v = "+luaString(n.canon(t.value)))
		}
	default:
		return no(t.op + " is not converted for nse")
	}
	if t.negated {
		kv = append(kv, "n = true")
	}
	return "{" + strings.Join(kv, ", ") + "}", Exact, "", true
}

// valuePattern is the regular expression the evaluator compiles for a
// string condition (eval.compileValue).
func valuePattern(raw, op string, cased bool) string {
	pat := wildcardRegexp(raw, true)
	switch op {
	case "contains":
	case "startswith":
		pat = "^" + pat
	case "endswith":
		pat += "$"
	default:
		pat = "^" + pat + "$"
	}
	if cased {
		return "(?s)" + pat
	}
	return "(?is)" + pat
}

// orbit is r and every rune it case-folds to, as Go's (?i) matches them.
func orbit(r rune) []rune {
	out := []rune{r}
	for f := unicode.SimpleFold(r); f != r; f = unicode.SimpleFold(f) {
		out = append(out, f)
	}
	return out
}

// canon folds a literal for case-insensitive comparison: every rune becomes
// the representative of its orbit, the ASCII lower-case letter where the
// orbit has one, else its smallest rune. The script folds responses the
// same way: ASCII letters to lower case, other runes by the fold table that
// collects the orbits used here. Comparing folded strings is then the same
// as Go's (?i) on the literal.
func (n *nse) canon(s string) string {
	var b strings.Builder
	for _, r := range s {
		o := orbit(r)
		rep := r
		for _, m := range o {
			rep = min(rep, m)
		}
		for _, m := range o {
			if m >= 'a' && m <= 'z' {
				rep = m
			}
		}
		for _, m := range o {
			if m != rep && m >= utf8.RuneSelf {
				n.fold[m] = rep
			}
		}
		b.WriteRune(rep)
	}
	return b.String()
}

// Pike VM operations in athar.nse.
const (
	luaAlt = iota + 1
	luaCap
	luaEmpty
	luaMatch
	luaFail
	luaNop
	luaRune
	luaAny
	luaAnyNotNL
)

// regex compiles a regular expression as Go's regexp package does and
// stores its program. It returns the program's 1-based index.
func (n *nse) regex(pat string) (int, error) {
	if i, ok := n.progIdx[pat]; ok {
		return i, nil
	}
	re, err := syntax.Parse(pat, syntax.Perl)
	if err != nil {
		return 0, err
	}
	prog, err := syntax.Compile(re.Simplify())
	if err != nil {
		return 0, err
	}
	var b strings.Builder
	fmt.Fprintf(&b, "{s = %d, ", prog.Start+1)
	if prog.StartCond()&syntax.EmptyBeginText != 0 {
		b.WriteString("a = true, ")
	}
	b.WriteString("i = {")
	for k, in := range prog.Inst {
		if k > 0 {
			b.WriteString(", ")
		}
		out := int(in.Out) + 1
		switch in.Op {
		case syntax.InstAlt, syntax.InstAltMatch:
			fmt.Fprintf(&b, "{%d, %d, %d}", luaAlt, out, in.Arg+1)
		case syntax.InstCapture:
			fmt.Fprintf(&b, "{%d, %d, %d}", luaCap, out, in.Arg)
		case syntax.InstEmptyWidth:
			fmt.Fprintf(&b, "{%d, %d, %d}", luaEmpty, out, in.Arg)
		case syntax.InstMatch:
			fmt.Fprintf(&b, "{%d}", luaMatch)
		case syntax.InstFail:
			fmt.Fprintf(&b, "{%d}", luaFail)
		case syntax.InstNop:
			fmt.Fprintf(&b, "{%d, %d}", luaNop, out)
		case syntax.InstRune, syntax.InstRune1:
			fmt.Fprintf(&b, "{%d, %d", luaRune, out)
			for _, r := range runeRanges(in) {
				fmt.Fprintf(&b, ", %d", r)
			}
			b.WriteString("}")
		case syntax.InstRuneAny:
			fmt.Fprintf(&b, "{%d, %d}", luaAny, out)
		case syntax.InstRuneAnyNotNL:
			fmt.Fprintf(&b, "{%d, %d}", luaAnyNotNL, out)
		default:
			return 0, fmt.Errorf("regexp instruction %v is not converted", in.Op)
		}
	}
	b.WriteString("}}")
	n.progs = append(n.progs, b.String())
	n.progIdx[pat] = len(n.progs)
	return len(n.progs), nil
}

// runeRanges returns the sorted rune ranges an instruction matches. A single
// rune with the fold flag stands for its whole orbit (syntax.Inst.MatchRune).
func runeRanges(in syntax.Inst) []rune {
	if in.Op == syntax.InstRune1 {
		return []rune{in.Rune[0], in.Rune[0]}
	}
	if len(in.Rune) != 1 {
		return in.Rune
	}
	set := []rune{in.Rune[0]}
	if syntax.Flags(in.Arg)&syntax.FoldCase != 0 {
		set = orbit(in.Rune[0])
	}
	sort.Slice(set, func(i, j int) bool { return set[i] < set[j] })
	var out []rune
	for _, r := range set {
		if len(out) > 0 && out[len(out)-1]+1 == r {
			out[len(out)-1] = r
		} else {
			out = append(out, r, r)
		}
	}
	return out
}

// lua writes a lowered expression as nested tables.
func (n *nse) lua(e expr, depth int) string {
	var op string
	var list []expr
	switch x := e.(type) {
	case lit:
		return x.s
	case andExpr:
		op, list = "and", x
	case orExpr:
		op, list = "or", x
	default:
		return "{}"
	}
	ind := strings.Repeat("  ", depth)
	var b strings.Builder
	b.WriteString(`{"` + op + `",`)
	for _, ch := range list {
		b.WriteString("\n" + ind + "  " + n.lua(ch, depth+1) + ",")
	}
	b.WriteString("\n" + ind + "}")
	return b.String()
}

var nseIDRe = regexp.MustCompile(`[^a-z0-9_-]+`)

// NSEID names a rule's data file: the rule's file name without extension.
func NSEID(r *rule.Rule) string {
	clean := func(s string) string {
		return strings.Trim(nseIDRe.ReplaceAllString(strings.ToLower(s), "_"), "_-")
	}
	s := ""
	if r.Path != "" {
		s = clean(strings.TrimSuffix(filepath.Base(r.Path), filepath.Ext(r.Path)))
	}
	if s == "" {
		s = clean(r.ID)
	}
	if s == "" {
		s = "rule"
	}
	return s
}

func convertNSE(r *rule.Rule) (Result, error) {
	res := Result{Engine: nseTarget}
	if strings.EqualFold(r.Target.Transport, "udp") {
		res.Fidelity = Unsupported
		res.Notes = []string{"athar.nse checks TCP services only, as athar scan does"}
		return res, nil
	}
	e, err := build(r)
	if err != nil {
		return Result{}, err
	}
	compiled, _, err := eval.Compile(r)
	if err != nil {
		return Result{}, err
	}
	n := &nse{r: r, fold: map[rune]rune{}, progIdx: map[string]int{}}
	c := &converter{b: n, engine: nseTarget}
	out := c.lower(nnf(e, false))
	res.Fidelity, res.Notes = c.fid, dedup(c.notes)
	if x, ok := out.(boolExpr); ok {
		res.Fidelity = Unsupported
		if bool(x) {
			res.Notes = append(res.Notes, "nothing convertible is left; the rule would match everything")
		} else {
			res.Notes = append(res.Notes, "the condition can never match")
		}
		return res, nil
	}
	cond := n.lua(out, 1)

	var entries []string
	add := func(k, v string) { entries = append(entries, "  "+k+" = "+v+",") }
	add("nse", strconv.Itoa(nseFormat))
	add("id", luaString(r.ID))
	add("title", luaString(r.Title))
	for _, kv := range [][2]string{
		{"author", r.Author}, {"product", r.Identifies.Product}, {"vendor", r.Identifies.Vendor},
		{"family", r.Identifies.Family}, {"category", r.Identifies.Category}, {"cpe", r.Identifies.CPE},
		{"confidence", r.Confidence},
	} {
		if kv[1] != "" {
			add(kv[0], luaString(kv[1]))
		}
	}
	// The families this rule is a variant of. athar.nse leaves a family out
	// when one of its variants matched, as athar scan does.
	var families []string
	for _, rel := range r.Related {
		if rel.Type == "variant-of" {
			families = append(families, luaString(rel.ID))
		}
	}
	if len(families) > 0 {
		add("variant_of", "{"+strings.Join(families, ", ")+"}")
	}
	tls := strings.ToLower(r.Target.TLS)
	if tls == "" {
		tls = "auto"
	}
	add("tls", luaString(tls))

	// What athar scan's prober would collect for this rule (scan.New).
	needs := map[string]bool{}
	if strings.ToLower(r.Target.Protocol) == "http" {
		needs["http"] = true
	} else {
		needs["banner"] = true
	}
	for id, fs := range compiled.FieldsUsed() {
		for _, f := range fs {
			switch {
			case strings.HasPrefix(f, "http.favicon."):
				needs["http"], needs["favicon"] = true, true
			case strings.HasPrefix(f, "http."):
				needs["http"] = true
			case strings.HasPrefix(f, "ssh."):
				needs["banner"] = true
			case f == "service.banner" && id == eval.DefaultProbe:
				needs["banner"] = true
			case f == "service.protocol" && id == eval.DefaultProbe:
				needs["banner"], needs["http"] = true, true
			}
		}
	}
	var nk []string
	for _, k := range []string{"banner", "http", "favicon"} {
		if needs[k] {
			nk = append(nk, k+" = true")
		}
	}
	add("needs", "{"+strings.Join(nk, ", ")+"}")

	probes, sent := nseProbes(r)
	if len(probes) > 0 {
		add("probes", "{\n    "+strings.Join(probes, ",\n    ")+",\n  }")
	}

	extract, notes := n.extract(r)
	res.Notes = append(res.Notes, notes...)
	if sent > 0 {
		plural := ""
		if sent > 1 {
			plural = "s"
		}
		res.Notes = append(res.Notes, fmt.Sprintf("declares %d custom probe%s, sent only with --script-args athar.probes (athar scan: -probes)", sent, plural))
	}
	add("fidelity", luaString(res.Fidelity.String()))
	if len(extract) > 0 {
		add("extract", "{\n    "+strings.Join(extract, ",\n    ")+",\n  }")
	}
	if len(n.fold) > 0 {
		keys := make([]rune, 0, len(n.fold))
		for k := range n.fold {
			keys = append(keys, k)
		}
		sort.Slice(keys, func(i, j int) bool { return keys[i] < keys[j] })
		var parts []string
		for _, k := range keys {
			parts = append(parts, "["+luaString(string(k))+"] = "+luaString(string(n.fold[k])))
		}
		add("fold", "{"+strings.Join(parts, ", ")+"}")
	}
	if len(n.progs) > 0 {
		add("re", "{\n    "+strings.Join(n.progs, ",\n    ")+",\n  }")
	}
	add("condition", cond)

	comment := func(s string) string { return strings.NewReplacer("\r", " ", "\n", " ").Replace(s) }
	var b strings.Builder
	fmt.Fprintf(&b, "-- Athar rule data for athar.nse, converted by athar convert from %s", comment(filepath.ToSlash(r.Path)))
	if r.ID != "" {
		fmt.Fprintf(&b, " (Athar rule %s)", comment(r.ID))
	}
	b.WriteString(".\n")
	if r.Author != "" {
		fmt.Fprintf(&b, "-- Rule by %s, licensed under the Detection Rule License 1.1:\n-- %s\n", comment(r.Author), DRLURL)
	}
	fmt.Fprintf(&b, "-- Fidelity: %s\n", res.Fidelity)
	for _, note := range res.Notes {
		fmt.Fprintf(&b, "-- Note: %s\n", comment(note))
	}
	b.WriteString("return {\n" + strings.Join(entries, "\n") + "\n}\n")
	res.TemplateID = NSEID(r)
	res.Template = b.String()
	return res, nil
}

// nseProbes writes the custom probes athar scan would send for the rule.
func nseProbes(r *rule.Rule) ([]string, int) {
	ids := make([]string, 0, len(r.Probes))
	for id := range r.Probes {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	var out []string
	for _, id := range ids {
		p := r.Probes[id]
		if len(p.Unsafe()) > 0 {
			continue
		}
		kv := []string{"key = " + luaString(probe.ProbeKey(p))}
		switch strings.ToLower(p.Protocol) {
		case "http":
			method, path := "GET", "/"
			var headers map[string]string
			if q := p.Request; q != nil {
				if q.Method != "" {
					method = strings.ToUpper(q.Method)
				}
				if q.Path != "" {
					path = q.Path
				}
				headers = q.Headers
			}
			kv = append(kv, `proto = "http"`, "method = "+luaString(method), "path = "+luaString(path))
			if len(headers) > 0 {
				names := make([]string, 0, len(headers))
				for k := range headers {
					names = append(names, k)
				}
				sort.Strings(names)
				var hs []string
				for _, k := range names {
					hs = append(hs, "["+luaString(k)+"] = "+luaString(headers[k]))
				}
				kv = append(kv, "headers = {"+strings.Join(hs, ", ")+"}")
			}
		case "tcp":
			kv = append(kv, `proto = "tcp"`)
			if p.Send != "" {
				b, err := rule.Unescape(p.Send)
				if err != nil {
					continue
				}
				kv = append(kv, "send = "+luaString(string(b)))
			}
			if q := p.Read; q != nil {
				if q.MaxBytes > 0 {
					kv = append(kv, "max = "+strconv.Itoa(min(q.MaxBytes, 8<<10)))
				}
				if q.TimeoutMs > 0 {
					kv = append(kv, "wait = "+strconv.Itoa(q.TimeoutMs))
				}
			}
		default:
			continue
		}
		out = append(out, "["+luaString(id)+"] = {"+strings.Join(kv, ", ")+"}")
	}
	return out, len(out)
}

// extract converts the rule's extract entries, which read the baseline
// response.
func (n *nse) extract(r *rule.Rule) ([]string, []string) {
	names := make([]string, 0, len(r.Extract))
	for k := range r.Extract {
		names = append(names, k)
	}
	sort.Strings(names)
	var out, notes []string
	for _, name := range names {
		x := r.Extract[name]
		if !nseField(x.Field) {
			notes = append(notes, fmt.Sprintf("extract %s reads %s, which athar.nse does not collect", name, x.Field))
			continue
		}
		kv := []string{"name = " + luaString(name), "f = " + luaString(x.Field)}
		switch {
		case x.Regex != "":
			re, err := regexp.Compile(x.Regex)
			if err != nil {
				continue
			}
			g := re.SubexpIndex(name)
			if g < 0 {
				g = min(1, re.NumSubexp())
			}
			i, err := n.regex(x.Regex)
			if err != nil {
				notes = append(notes, fmt.Sprintf("extract %s: %v", name, err))
				continue
			}
			kv = append(kv, "r = "+strconv.Itoa(i), "g = "+strconv.Itoa(g))
		case x.JSONPath != "":
			var segs []string
			for _, s := range strings.Split(strings.TrimPrefix(x.JSONPath, "$."), ".") {
				segs = append(segs, luaString(s))
			}
			kv = append(kv, "j = {"+strings.Join(segs, ", ")+"}")
			notes = append(notes, fmt.Sprintf("extract %s parses JSON with Nmap's json library, which may read malformed JSON differently", name))
		default:
			continue
		}
		out = append(out, "{"+strings.Join(kv, ", ")+"}")
	}
	return out, notes
}

// luaString writes a Lua string literal. Valid UTF-8 stays readable; other
// bytes and control characters are escaped.
func luaString(s string) string {
	valid := utf8.ValidString(s)
	var b strings.Builder
	b.WriteByte('"')
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c == '"' || c == '\\':
			b.WriteByte('\\')
			b.WriteByte(c)
		case c == '\n':
			b.WriteString(`\n`)
		case c == '\r':
			b.WriteString(`\r`)
		case c == '\t':
			b.WriteString(`\t`)
		case c < 0x20 || c == 0x7f || (c >= 0x80 && !valid):
			fmt.Fprintf(&b, `\x%02x`, c)
		default:
			b.WriteByte(c)
		}
	}
	b.WriteByte('"')
	return b.String()
}

// luaNumber writes a number literal. The data files run without libraries,
// so infinities are written as divisions.
func luaNumber(f float64) string {
	switch {
	case math.IsInf(f, 1):
		return "(1/0)"
	case math.IsInf(f, -1):
		return "(-1/0)"
	case math.IsNaN(f):
		return "(0/0)"
	}
	if f == math.Trunc(f) && math.Abs(f) < 1<<53 {
		return strconv.FormatInt(int64(f), 10)
	}
	return strconv.FormatFloat(f, 'g', -1, 64)
}
