// Package eval is the Athar evaluator: it decides whether a rule matches a
// service and extracts values. The same code judges rule tests, engine records
// and live responses (spec section 1, "the scanner defines meaning").
package eval

import (
	"encoding/json"
	"fmt"
	"regexp"
	"sort"
	"strings"

	"github.com/Athar-HQ/Athar/cli/internal/condition"
	"github.com/Athar-HQ/Athar/cli/internal/fields"
	"github.com/Athar-HQ/Athar/cli/internal/rule"
)

// DefaultProbe is the baseline probe every rule implicitly uses.
const DefaultProbe = "default"

// Fields are the taxonomy fields of one response. Values are scalars or lists
// of scalars. A missing key means the field is absent.
type Fields map[string]any

// Responses holds the fields per probe id for one service.
type Responses map[string]Fields

// Result of evaluating a rule against one service.
type Result struct {
	Match     bool
	Matched   []string          // selections that held, sorted
	Extracted map[string]string // only set when Match is true
}

// Compiled is a rule ready for evaluation.
type Compiled struct {
	Rule       *rule.Rule
	selections map[string]selection
	cond       condition.Node
	extract    []extractor
}

// Compile checks a rule's detection and extract sections and prepares them
// for evaluation. Unused selections are reported as warnings.
func Compile(r *rule.Rule) (*Compiled, []rule.Problem, error) {
	c := &Compiled{Rule: r, selections: map[string]selection{}}
	var warnings []rule.Problem

	condValue, ok := r.Detection["condition"]
	if !ok {
		return nil, nil, fmt.Errorf("detection: missing condition")
	}
	condStr, ok := condValue.(string)
	if !ok {
		return nil, nil, fmt.Errorf("detection: condition must be a single string")
	}

	var names []string
	for name, v := range r.Detection {
		if name == "condition" {
			continue
		}
		s, err := compileSelection(name, v, r.Probes)
		if err != nil {
			return nil, nil, fmt.Errorf("detection: %w", err)
		}
		c.selections[name] = s
		names = append(names, name)
	}
	if len(names) == 0 {
		return nil, nil, fmt.Errorf("detection: no selections")
	}

	cond, err := condition.Parse(condStr, names)
	if err != nil {
		return nil, nil, fmt.Errorf("detection: condition: %w", err)
	}
	c.cond = cond

	used := map[string]bool{}
	for _, n := range cond.Names(nil) {
		used[n] = true
	}
	sort.Strings(names)
	for _, n := range names {
		if !used[n] {
			warnings = append(warnings, rule.Problem{Severity: rule.Warning, Msg: fmt.Sprintf("selection %q is not used in the condition", n)})
		}
	}

	extractNames := make([]string, 0, len(r.Extract))
	for name := range r.Extract {
		extractNames = append(extractNames, name)
	}
	sort.Strings(extractNames)
	for _, name := range extractNames {
		x, err := compileExtract(name, r.Extract[name])
		if err != nil {
			return nil, nil, fmt.Errorf("extract %s: %w", name, err)
		}
		c.extract = append(c.extract, x)
	}

	return c, warnings, nil
}

// Eval evaluates the rule against the responses of one service.
func (c *Compiled) Eval(resp Responses) Result {
	truth := make(map[string]bool, len(c.selections))
	var res Result
	for name, s := range c.selections {
		if s.match(resp) {
			truth[name] = true
			res.Matched = append(res.Matched, name)
		}
	}
	sort.Strings(res.Matched)
	res.Match = c.cond.Eval(truth)
	if res.Match {
		res.Extracted = c.runExtract(resp[DefaultProbe])
	}
	return res
}

// selection is one named search identifier of the detection block.
type selection interface{ match(Responses) bool }

// mapSelection is a map of field conditions (AND), bound to one probe.
type mapSelection struct {
	probe    string
	matchers []*fieldMatcher
}

func (s *mapSelection) match(resp Responses) bool {
	f, ok := resp[s.probe]
	if !ok {
		return false
	}
	for _, m := range s.matchers {
		if !m.match(f) {
			return false
		}
	}
	return true
}

// anySelection is a list of maps (OR).
type anySelection []*mapSelection

func (s anySelection) match(resp Responses) bool {
	for _, m := range s {
		if m.match(resp) {
			return true
		}
	}
	return false
}

// keywordSelection is a list of strings searched in the keyword fields of the
// baseline response (OR).
type keywordSelection []valueMatcher

func (s keywordSelection) match(resp Responses) bool {
	f := resp[DefaultProbe]
	for _, vm := range s {
		for _, name := range fields.Keyword {
			if v, ok := f[name]; ok && v != nil && anyElement(v, vm) {
				return true
			}
		}
	}
	return false
}

func compileSelection(name string, v any, probes map[string]rule.Probe) (selection, error) {
	switch x := v.(type) {
	case map[string]any:
		return compileMap(name, x, probes)
	case []any:
		if len(x) == 0 {
			return nil, fmt.Errorf("%s: empty selection", name)
		}
		if _, isMap := x[0].(map[string]any); isMap {
			var out anySelection
			for _, e := range x {
				m, ok := e.(map[string]any)
				if !ok {
					return nil, fmt.Errorf("%s: a list of maps can't also contain plain values", name)
				}
				s, err := compileMap(name, m, probes)
				if err != nil {
					return nil, err
				}
				out = append(out, s)
			}
			return out, nil
		}
		return compileKeywords(name, x)
	case string:
		return compileKeywords(name, []any{x})
	case nil:
		return nil, fmt.Errorf("%s: empty selection", name)
	}
	return nil, fmt.Errorf("%s: a selection is a map, a list of maps or a list of keywords", name)
}

func compileMap(name string, m map[string]any, probes map[string]rule.Probe) (*mapSelection, error) {
	s := &mapSelection{probe: DefaultProbe}
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		if k == "probe" {
			p, ok := m[k].(string)
			if !ok || p == "" {
				return nil, fmt.Errorf("%s: probe must be a probe id", name)
			}
			if _, declared := probes[p]; !declared && p != DefaultProbe {
				return nil, fmt.Errorf("%s: probe %q is not declared under probes", name, p)
			}
			s.probe = p
			continue
		}
		field, _, _ := strings.Cut(k, "|")
		if !fields.Known(field) {
			return nil, fmt.Errorf("%s: unknown field %q", name, field)
		}
		fm, err := compileField(k, m[k])
		if err != nil {
			return nil, fmt.Errorf("%s: %w", name, err)
		}
		s.matchers = append(s.matchers, fm)
	}
	if len(s.matchers) == 0 {
		return nil, fmt.Errorf("%s: no field conditions", name)
	}
	return s, nil
}

func compileKeywords(name string, list []any) (keywordSelection, error) {
	var out keywordSelection
	for _, e := range list {
		switch e.(type) {
		case map[string]any, []any, nil:
			return nil, fmt.Errorf("%s: keywords must be plain values", name)
		}
		vm, err := compileValue("contains", toString(e), false, false)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", name, err)
		}
		out = append(out, vm)
	}
	return out, nil
}

// extractor pulls one named value from the baseline response.
type extractor struct {
	name  string
	field string
	re    *regexp.Regexp
	group int
	path  []string // JSON path segments for jsonpath
}

func compileExtract(name string, x rule.Extract) (extractor, error) {
	e := extractor{name: name, field: x.Field}
	if x.Field == "" {
		return e, fmt.Errorf("missing field")
	}
	if !fields.Known(x.Field) {
		return e, fmt.Errorf("unknown field %q", x.Field)
	}
	switch {
	case x.Regex != "" && x.JSONPath != "":
		return e, fmt.Errorf("use either regex or jsonpath, not both")
	case x.Regex != "":
		re, err := regexp.Compile(x.Regex)
		if err != nil {
			return e, err
		}
		e.re = re
		// Take the group named like the value, else the first group, else
		// the whole match.
		e.group = re.SubexpIndex(name)
		if e.group < 0 {
			e.group = min(1, re.NumSubexp())
		}
	case x.JSONPath != "":
		rest, ok := strings.CutPrefix(x.JSONPath, "$.")
		if !ok || rest == "" || strings.ContainsAny(rest, "[]*") {
			return e, fmt.Errorf("jsonpath %q: only dotted paths like $.a.b are supported for now", x.JSONPath)
		}
		e.path = strings.Split(rest, ".")
	default:
		return e, fmt.Errorf("needs a regex or a jsonpath")
	}
	return e, nil
}

func (c *Compiled) runExtract(f Fields) map[string]string {
	if len(c.extract) == 0 {
		return nil
	}
	out := map[string]string{}
	for _, x := range c.extract {
		v, ok := f[x.field]
		if !ok || v == nil {
			continue
		}
		values, isList := v.([]any)
		if !isList {
			values = []any{v}
		}
		for _, e := range values {
			if s, ok := x.apply(toString(e)); ok {
				out[x.name] = s
				break
			}
		}
	}
	return out
}

func (x extractor) apply(s string) (string, bool) {
	if x.re != nil {
		m := x.re.FindStringSubmatch(s)
		if m == nil {
			return "", false
		}
		return m[x.group], true
	}
	var doc any
	if err := json.Unmarshal([]byte(s), &doc); err != nil {
		return "", false
	}
	for _, seg := range x.path {
		obj, ok := doc.(map[string]any)
		if !ok {
			return "", false
		}
		if doc, ok = obj[seg]; !ok {
			return "", false
		}
	}
	switch doc.(type) {
	case map[string]any, []any, nil:
		return "", false
	}
	return toString(doc), true
}
