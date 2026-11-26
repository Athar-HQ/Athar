package eval

import (
	"errors"
	"fmt"
	"sort"
	"strings"

	"github.com/Athar-HQ/Athar/cli/internal/fields"
	"github.com/Athar-HQ/Athar/cli/internal/rule"
)

// RawHTTP derives the fields of one HTTP response, given as received, for
// tests with a raw response. The scanner's parser is in package probe, which
// imports this package, so the program sets it: eval.RawHTTP = probe.HTTPFields.
var RawHTTP func(raw []byte) (Fields, error)

// TestResult is the outcome of one entry in a rule's tests section.
type TestResult struct {
	Name   string
	Passed bool
	Detail string // why it failed
}

// RunTests evaluates the rule's tests (spec section 9). raw and response
// describe the baseline probe and probes the custom probes, by id; a custom
// probe a test doesn't list got no response.
func (c *Compiled) RunTests() []TestResult {
	var out []TestResult
	for i, t := range c.Rule.Tests {
		name := t.Name
		if name == "" {
			name = fmt.Sprintf("#%d", i+1)
		}
		tr := TestResult{Name: name, Passed: true}

		var unknown []string
		for f := range t.Response {
			if !fields.Known(f) {
				unknown = append(unknown, f)
			}
		}
		for id, pr := range t.Probes {
			for f, v := range pr {
				if _, ok := v.(string); ok && f == "raw" {
					continue
				}
				if !fields.Known(f) {
					unknown = append(unknown, id+": "+f)
				}
			}
		}
		sort.Strings(unknown)
		if len(unknown) > 0 {
			tr.Passed = false
			tr.Detail = "unknown field(s) in response: " + strings.Join(unknown, ", ")
			out = append(out, tr)
			continue
		}

		var bad []string
		base, err := testFields(t.Raw, t.Response)
		if err != nil {
			bad = append(bad, err.Error())
		}
		resp := Responses{DefaultProbe: base}
		for id, pr := range t.Probes {
			raw, _ := pr["raw"].(string)
			if resp[id], err = testFields(raw, pr); err != nil {
				bad = append(bad, "probe "+id+": "+err.Error())
			}
		}
		if len(bad) > 0 {
			sort.Strings(bad)
			tr.Passed = false
			tr.Detail = strings.Join(bad, "; ")
			out = append(out, tr)
			continue
		}
		res := c.Eval(resp)
		switch {
		case t.Expect == "match" && !res.Match:
			tr.Passed = false
			tr.Detail = fmt.Sprintf("expected match, got no_match (selections that held: %s)", list(res.Matched))
		case t.Expect == "no_match" && res.Match:
			tr.Passed = false
			tr.Detail = fmt.Sprintf("expected no_match, got match (selections that held: %s)", list(res.Matched))
		case t.Expect != "match" && t.Expect != "no_match":
			tr.Passed = false
			tr.Detail = fmt.Sprintf("expect must be match or no_match, got %q", t.Expect)
		}
		if tr.Passed && len(t.Extracted) > 0 {
			if t.Expect != "match" {
				tr.Passed = false
				tr.Detail = "extracted values can only be checked on expect: match"
			} else {
				var diffs []string
				keys := make([]string, 0, len(t.Extracted))
				for k := range t.Extracted {
					keys = append(keys, k)
				}
				sort.Strings(keys)
				for _, k := range keys {
					got, ok := res.Extracted[k]
					if !ok {
						diffs = append(diffs, fmt.Sprintf("%s: want %q, got nothing", k, t.Extracted[k]))
					} else if got != t.Extracted[k] {
						diffs = append(diffs, fmt.Sprintf("%s: want %q, got %q", k, t.Extracted[k], got))
					}
				}
				if len(diffs) > 0 {
					tr.Passed = false
					tr.Detail = "extracted " + strings.Join(diffs, "; ")
				}
			}
		}
		out = append(out, tr)
	}
	return out
}

// testFields returns the fields of one test response: the ones derived from
// raw, if given, and the listed ones on top.
func testFields(raw string, listed map[string]any) (Fields, error) {
	f := Fields{}
	if raw != "" {
		if RawHTTP == nil {
			return nil, errors.New("raw: no HTTP parser set (eval.RawHTTP)")
		}
		var err error
		if f, err = RawHTTP(rule.RawResponse(raw)); err != nil {
			return nil, fmt.Errorf("raw: %w", err)
		}
	}
	for k, v := range listed {
		if k != "raw" {
			f[k] = v
		}
	}
	return f, nil
}

func list(s []string) string {
	if len(s) == 0 {
		return "none"
	}
	return strings.Join(s, ", ")
}
