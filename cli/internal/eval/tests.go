package eval

import (
	"fmt"
	"sort"
	"strings"

	"github.com/Athar-HQ/Athar/cli/internal/fields"
)

// TestResult is the outcome of one entry in a rule's tests section.
type TestResult struct {
	Name   string
	Passed bool
	Detail string // why it failed
}

// RunTests evaluates the rule's tests (spec section 9). Test responses
// describe the baseline probe.
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
		sort.Strings(unknown)
		if len(unknown) > 0 {
			tr.Passed = false
			tr.Detail = "unknown field(s) in response: " + strings.Join(unknown, ", ")
			out = append(out, tr)
			continue
		}

		res := c.Eval(Responses{DefaultProbe: Fields(t.Response)})
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

func list(s []string) string {
	if len(s) == 0 {
		return "none"
	}
	return strings.Join(s, ", ")
}
