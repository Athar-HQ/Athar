package condition

import "testing"

func TestEval(t *testing.T) {
	names := []string{"selection_title", "selection_route", "selection_icon", "filter_known", "_helper"}
	truth := map[string]bool{"selection_title": true, "selection_route": true, "_helper": false}

	tests := []struct {
		cond string
		want bool
	}{
		{"selection_title", true},
		{"selection_title and selection_route", true},
		{"selection_title and selection_icon", false},
		{"selection_icon or selection_route", true},
		{"selection_title and not filter_known", true},
		{"not selection_title", false},
		{"not not selection_title", true},
		// and binds tighter than or
		{"selection_icon and selection_title or selection_route", true},
		{"selection_icon and (selection_title or selection_route)", false},
		// not binds tighter than and
		{"not selection_icon and selection_title", true},
		{"not (selection_icon or selection_title)", false},
		{"1 of selection_*", true},
		{"all of selection_*", false},
		{"all of selection_t* and all of selection_r*", true},
		{"1 of filter_*", false},
		{"not 1 of filter_*", true},
		// "them" skips names starting with an underscore
		{"all of them", false},
		{"1 of them", true},
		{"selection_title AND selection_route", true}, // keywords are case-insensitive
	}
	for _, tt := range tests {
		n, err := Parse(tt.cond, names)
		if err != nil {
			t.Errorf("Parse(%q): %v", tt.cond, err)
			continue
		}
		if got := n.Eval(truth); got != tt.want {
			t.Errorf("Eval(%q) = %v, want %v", tt.cond, got, tt.want)
		}
	}
}

func TestAllOfThemExcludesUnderscore(t *testing.T) {
	n, err := Parse("all of them", []string{"a", "b", "_c"})
	if err != nil {
		t.Fatal(err)
	}
	if !n.Eval(map[string]bool{"a": true, "b": true}) {
		t.Error(`"all of them" should ignore _c`)
	}
}

func TestParseErrors(t *testing.T) {
	names := []string{"selection", "filter"}
	for _, cond := range []string{
		"",
		"unknown",
		"selection and",
		"selection or or filter",
		"(selection",
		"selection)",
		"1 of",
		"1 of nomatch_*",
		"all selection",
		"and selection",
		"not",
		"1 of selection filter", // one pattern per "of"
		"SELECTION",             // identifiers are case-sensitive
	} {
		if _, err := Parse(cond, names); err == nil {
			t.Errorf("Parse(%q): want error", cond)
		}
	}
}

func TestNames(t *testing.T) {
	n, err := Parse("1 of sel_* and not filter", []string{"sel_a", "sel_b", "filter", "unused"})
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]bool{}
	for _, name := range n.Names(nil) {
		got[name] = true
	}
	for _, want := range []string{"sel_a", "sel_b", "filter"} {
		if !got[want] {
			t.Errorf("Names() misses %q", want)
		}
	}
	if got["unused"] {
		t.Error(`Names() includes "unused"`)
	}
}
