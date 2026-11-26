// Package convert turns rules into search-engine queries (spec section 10),
// Nuclei templates and data files for the Nmap script athar.nse.
//
// A rule's condition and selections become one boolean expression. Negations
// are pushed down to single conditions, each condition is translated by the
// engine backend, and conditions an engine can't express are replaced with
// TRUE, so the query can only over-match (the superset rule). Every result
// carries a fidelity label and the reasons for it.
package convert

import (
	"fmt"
	"sort"
	"strconv"
	"strings"
	"unicode"

	"github.com/Athar-HQ/Athar/cli/internal/condition"
	"github.com/Athar-HQ/Athar/cli/internal/rule"
)

// Fidelity says how close a query is to the rule (spec section 10).
type Fidelity int

const (
	Exact       Fidelity = iota // same result set as the scanner on the engine's data
	Approximate                 // same intent, looser or differently tokenised operator
	Superset                    // unconvertible parts dropped; can only over-match
	Unsupported                 // nothing meaningful left
)

func (f Fidelity) String() string {
	return [...]string{"exact", "approximate", "superset", "unsupported"}[f]
}

func (f Fidelity) MarshalText() ([]byte, error) { return []byte(f.String()), nil }

// Engines lists the supported search engines in output order.
var Engines = []string{"fofa", "shodan", "censys", "zoomeye", "modat", "urlscan"}

// Scanners lists the scanners rules convert to as templates.
var Scanners = []string{nucleiTarget, nseTarget}

// Result is one rule converted for one engine or scanner.
type Result struct {
	Engine     string   `json:"engine"`
	Query      string   `json:"query,omitempty"`
	TemplateID string   `json:"template_id,omitempty"`
	Template   string   `json:"template,omitempty"`
	Fidelity   Fidelity `json:"fidelity"`
	Notes      []string `json:"notes,omitempty"`
}

// Convert converts a rule that passed eval.Compile for one engine or
// scanner.
func Convert(r *rule.Rule, engine string) (Result, error) {
	switch engine {
	case nucleiTarget:
		return convertNuclei(r)
	case nseTarget:
		return convertNSE(r)
	}
	b, ok := backends[engine]
	if !ok {
		return Result{}, fmt.Errorf("unknown target %q (supported: %s, %s)", engine, strings.Join(Engines, ", "), strings.Join(Scanners, ", "))
	}
	e, err := build(r)
	if err != nil {
		return Result{}, err
	}
	c := &converter{b: b, engine: engine}
	out := c.lower(nnf(e, false))
	res := Result{Engine: engine, Fidelity: c.fid, Notes: dedup(c.notes)}
	switch x := out.(type) {
	case boolExpr:
		res.Fidelity = Unsupported
		if bool(x) {
			res.Notes = append(res.Notes, "nothing convertible is left; the query would match everything")
		} else {
			res.Notes = append(res.Notes, "the condition can never match")
		}
		return res, nil
	}
	res.Query = b.wrap(c.render(out, false))
	if n, ok := b.(engineNoter); ok {
		res.Notes = append(res.Notes, n.notes()...)
	}
	return res, nil
}

// probeTermer is implemented by engines that index more than the baseline
// probe sees. urlscan hashes every file a page loads, so the hash of a file a
// custom probe fetches can still be searched.
type probeTermer interface {
	probeTerm(t term) (s string, f Fidelity, note string, ok bool)
}

// engineNoter is implemented by engines whose data differs from the
// scanner's in a way that applies to every query.
type engineNoter interface{ notes() []string }

// negGrouper is implemented by engines with Lucene's boolean syntax, where a
// NOT next to OR excludes from the whole group: a OR NOT b finds a and not b.
// A negation inside an OR is put in its own group, a OR (NOT b), which keeps
// its meaning.
type negGrouper interface{ groupNegation() }

// ---- expression tree ----

type expr interface{}
type andExpr []expr
type orExpr []expr
type notExpr struct{ x expr }
type boolExpr bool

// term is one condition on one field, or a keyword when field is empty.
type term struct {
	field   string
	op      string // eq, contains, startswith, endswith, re, exists, gt, gte, lt, lte, cidr, null
	value   string // literal value (wildcard escapes resolved unless wild)
	raw     string // value as written in the rule
	wild    bool   // value contains unescaped * or ?
	cased   bool
	hex     bool
	probe   string
	negated bool
}

// lit is a term an engine could express, already rendered. key and val are
// set by engines that can OR several values of one field (see keyer); neg
// is set when the term is negated.
type lit struct {
	s, key, val string
	neg         bool
}

// keyer is implemented by engines without a general OR that can still list
// several values for one field, as Shodan does with http.title:"a","b".
type keyer interface {
	key(t term) (field, value string)
	list(field string, values []string) string
}

func build(r *rule.Rule) (expr, error) {
	cond, _ := r.Detection["condition"].(string)
	var names []string
	for k := range r.Detection {
		if k != "condition" {
			names = append(names, k)
		}
	}
	n, err := condition.Parse(cond, names)
	if err != nil {
		return nil, err
	}
	return fromNode(n, r.Detection), nil
}

func fromNode(n condition.Node, det map[string]any) expr {
	switch x := n.(type) {
	case condition.Ident:
		return selection(det[string(x)])
	case condition.Not:
		return notExpr{fromNode(x.X, det)}
	case condition.And:
		out := andExpr{}
		for _, c := range x {
			out = append(out, fromNode(c, det))
		}
		return out
	case condition.Or:
		out := orExpr{}
		for _, c := range x {
			out = append(out, fromNode(c, det))
		}
		return out
	}
	return boolExpr(true)
}

func selection(v any) expr {
	switch x := v.(type) {
	case map[string]any:
		return fieldMap(x)
	case []any:
		out := orExpr{}
		for _, e := range x {
			if m, ok := e.(map[string]any); ok {
				out = append(out, fieldMap(m))
			} else {
				out = append(out, keyword(e))
			}
		}
		return out
	default:
		return keyword(x)
	}
}

func keyword(v any) expr {
	s := valueString(v)
	lit, wild := unwildcard(s)
	return term{op: "contains", value: lit, raw: s, wild: wild, probe: "default"}
}

func fieldMap(m map[string]any) expr {
	probe := "default"
	if p, ok := m["probe"].(string); ok {
		probe = p
	}
	keys := make([]string, 0, len(m))
	for k := range m {
		if k != "probe" {
			keys = append(keys, k)
		}
	}
	sort.Strings(keys)
	out := andExpr{}
	for _, k := range keys {
		out = append(out, fieldExpr(k, m[k], probe))
	}
	if len(out) == 1 {
		return out[0]
	}
	return out
}

func fieldExpr(key string, v any, probe string) expr {
	parts := strings.Split(key, "|")
	t := term{field: parts[0], op: "eq", probe: probe}
	all := false
	for _, mod := range parts[1:] {
		switch mod {
		case "all":
			all = true
		case "cased":
			t.cased = true
		case "hex":
			t.hex = true
		default:
			t.op = mod
		}
	}
	if v == nil {
		t.op = "null"
		return t
	}
	if t.op == "exists" {
		t.value = valueString(v)
		return t
	}
	values, ok := v.([]any)
	if !ok {
		values = []any{v}
	}
	var group []expr
	for _, val := range values {
		tt := t
		tt.raw = valueString(val)
		tt.value = tt.raw
		if t.op != "re" && !t.hex {
			tt.value, tt.wild = unwildcard(tt.raw)
		}
		group = append(group, tt)
	}
	if len(group) == 1 {
		return group[0]
	}
	if all {
		return andExpr(group)
	}
	return orExpr(group)
}

// nnf pushes negations down to the terms.
func nnf(e expr, neg bool) expr {
	switch x := e.(type) {
	case andExpr:
		out := make([]expr, len(x))
		for i, c := range x {
			out[i] = nnf(c, neg)
		}
		if neg {
			return orExpr(out)
		}
		return andExpr(out)
	case orExpr:
		out := make([]expr, len(x))
		for i, c := range x {
			out[i] = nnf(c, neg)
		}
		if neg {
			return andExpr(out)
		}
		return orExpr(out)
	case notExpr:
		return nnf(x.x, !neg)
	case term:
		x.negated = neg
		return x
	case boolExpr:
		return boolExpr(bool(x) != neg)
	}
	return e
}

// ---- lowering and rendering ----

type converter struct {
	b      backend
	engine string
	fid    Fidelity
	notes  []string
}

func (c *converter) worse(f Fidelity) {
	if f > c.fid {
		c.fid = f
	}
}

func (c *converter) drop(note string) expr {
	c.worse(Superset)
	c.notes = append(c.notes, note+" (dropped)")
	return boolExpr(true)
}

// lower translates terms bottom-up and simplifies. In negation normal form
// every term that can't be expressed becomes TRUE, which only widens the
// query.
func (c *converter) lower(e expr) expr {
	switch x := e.(type) {
	case term:
		var (
			s, note string
			f       Fidelity
			ok      bool
		)
		_, query := backends[c.engine]
		if pt, can := c.b.(probeTermer); query && strings.ContainsFunc(x.raw, unicode.IsControl) {
			// A search-engine query is one line, and only Censys documents
			// escapes for line breaks and tabs.
			note = fmt.Sprintf("%s: control characters such as line breaks are not written into %s queries", describe(x), c.engine)
		} else if x.probe == "default" {
			s, f, note, ok = c.b.term(x)
		} else if can {
			s, f, note, ok = pt.probeTerm(x)
		} else {
			note = fmt.Sprintf("%s uses the custom probe %q, which engines don't index", describe(x), x.probe)
		}
		if !ok {
			return c.drop(note)
		}
		if how := caseLost(c.engine, x); how != "" {
			// A search that ignores case finds more than the term, so its
			// negation finds less.
			if x.negated {
				return c.drop(widenedNote(x, how))
			}
			f, note = max(f, Approximate), joinNote(note, how)
		}
		if note != "" {
			c.notes = append(c.notes, note)
		}
		if fieldTables[c.engine][x.field].unverified {
			// Nobody checked that the engine field holds what the rule
			// field holds, so the query can't be called exact.
			c.worse(Approximate)
		}
		c.worse(f)
		l := lit{s: s, neg: x.negated}
		if k, ok := c.b.(keyer); ok {
			l.key, l.val = k.key(x)
		}
		return l
	case andExpr:
		var out andExpr
		for _, ch := range x {
			switch l := c.lower(ch).(type) {
			case boolExpr:
				if !l {
					return boolExpr(false)
				}
			case andExpr:
				out = append(out, l...)
			default:
				out = append(out, l)
			}
		}
		switch len(out) {
		case 0:
			return boolExpr(true)
		case 1:
			return out[0]
		}
		return out
	case orExpr:
		// Notes from alternatives that end up dropped would describe
		// conditions that are not in the query, so they are discarded.
		start := len(c.notes)
		var out orExpr
		for _, ch := range x {
			childStart := len(c.notes)
			switch l := c.lower(ch).(type) {
			case boolExpr:
				if l {
					c.notes = append(c.notes[:start], c.notes[childStart:]...)
					return boolExpr(true)
				}
			case orExpr:
				out = append(out, l...)
			default:
				out = append(out, l)
			}
		}
		switch len(out) {
		case 0:
			return boolExpr(false)
		case 1:
			return out[0]
		}
		if !c.b.canOr() {
			if merged, ok := c.sameField(out); ok {
				return merged
			}
			c.notes = c.notes[:start]
			return c.drop(fmt.Sprintf("%s can only OR values of one filter, not %s", c.engine, describeExpr(x)))
		}
		return out
	case boolExpr:
		return x
	}
	return boolExpr(true)
}

// sameField merges an OR of values of one field into the engine's value
// list, if the engine has one.
func (c *converter) sameField(alts orExpr) (expr, bool) {
	k, ok := c.b.(keyer)
	if !ok {
		return nil, false
	}
	var key string
	var vals []string
	for _, a := range alts {
		l, ok := a.(lit)
		if !ok || l.key == "" || (key != "" && l.key != key) {
			return nil, false
		}
		key = l.key
		vals = append(vals, l.val)
	}
	s := k.list(key, vals)
	return lit{s: s, key: key, val: strings.Join(vals, ",")}, true
}

func (c *converter) render(e expr, nested bool) string {
	switch x := e.(type) {
	case lit:
		return x.s
	case andExpr:
		parts := make([]string, len(x))
		for i, ch := range x {
			parts[i] = c.render(ch, true)
		}
		s := strings.Join(parts, c.b.andOp())
		if nested {
			return "(" + s + ")"
		}
		return s
	case orExpr:
		_, group := c.b.(negGrouper)
		parts := make([]string, len(x))
		for i, ch := range x {
			parts[i] = c.render(ch, true)
			if l, ok := ch.(lit); ok && l.neg && group {
				parts[i] = "(" + parts[i] + ")"
			}
		}
		s := strings.Join(parts, c.b.orOp())
		if nested {
			return "(" + s + ")"
		}
		return s
	}
	return ""
}

// ---- helpers shared by backends ----

func valueString(v any) string {
	switch x := v.(type) {
	case string:
		return x
	case int:
		return strconv.Itoa(x)
	case int64:
		return strconv.FormatInt(x, 10)
	case uint64:
		return strconv.FormatUint(x, 10)
	case float64:
		return strconv.FormatFloat(x, 'f', -1, 64)
	case bool:
		return strconv.FormatBool(x)
	}
	return fmt.Sprint(v)
}

// unwildcard resolves Sigma's \*, \? and \\ escapes and reports whether the
// value still contains a real wildcard.
func unwildcard(s string) (string, bool) {
	var b strings.Builder
	wild := false
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c == '\\' && i+1 < len(s) && (s[i+1] == '*' || s[i+1] == '?' || s[i+1] == '\\'):
			b.WriteByte(s[i+1])
			i++
		case c == '*' || c == '?':
			wild = true
			b.WriteByte(c)
		default:
			b.WriteByte(c)
		}
	}
	return b.String(), wild
}

// quote wraps s in double quotes and escapes backslashes and quotes.
func quote(s string) string {
	return `"` + strings.NewReplacer(`\`, `\\`, `"`, `\"`).Replace(s) + `"`
}

// quoteRegex wraps a Modat regex or wildcard pattern in double quotes,
// escaping only the quotes, so escapes such as \. and \* stay as they are.
// The pattern must not have a backslash in front of a quote or at its end;
// modatValue, modatRegex and modatLiteral see to that.
func quoteRegex(re string) string {
	return `"` + strings.ReplaceAll(re, `"`, `\"`) + `"`
}

// escapeRunes puts a backslash in front of every character of s that is in
// special.
func escapeRunes(s, special string) string {
	var b strings.Builder
	for _, r := range s {
		if strings.ContainsRune(special, r) {
			b.WriteByte('\\')
		}
		b.WriteRune(r)
	}
	return b.String()
}

// regexLiteral escapes every ASCII punctuation character, which is valid in
// RE2 and in Lucene-style regex dialects alike.
func regexLiteral(s string) string {
	var b strings.Builder
	for _, r := range s {
		if r < 128 && r != ' ' && !(r >= '0' && r <= '9') && !(r >= 'a' && r <= 'z') && !(r >= 'A' && r <= 'Z') {
			b.WriteByte('\\')
		}
		b.WriteRune(r)
	}
	return b.String()
}

func describe(t term) string {
	if t.field == "" {
		return fmt.Sprintf("keyword %q", t.raw)
	}
	op := t.op
	if op == "eq" {
		return fmt.Sprintf("%s = %q", t.field, t.raw)
	}
	return fmt.Sprintf("%s|%s %q", t.field, op, t.raw)
}

// describeExpr writes a negation-normal-form expression in rule terms.
func describeExpr(e expr) string {
	switch x := e.(type) {
	case term:
		if x.negated {
			return "not " + describe(x)
		}
		return describe(x)
	case andExpr, orExpr:
		var parts []string
		join := " and "
		list, _ := x.(andExpr)
		if o, ok := x.(orExpr); ok {
			list, join = andExpr(o), " or "
		}
		for _, ch := range list {
			parts = append(parts, describeExpr(ch))
		}
		return "(" + strings.Join(parts, join) + ")"
	}
	return fmt.Sprint(e)
}

func dedup(s []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, v := range s {
		if !seen[v] {
			seen[v] = true
			out = append(out, v)
		}
	}
	return out
}
