package eval

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/Athar-HQ/Athar/cli/internal/rule"
)

// compile builds a rule from a YAML detection (and optional extra top-level
// YAML) and fails the test on errors.
func compile(t *testing.T, detection string, extra ...string) *Compiled {
	t.Helper()
	c, _, err := compileErr(detection, extra...)
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}
	return c
}

func compileErr(detection string, extra ...string) (*Compiled, []rule.Problem, error) {
	src := "title: t\ndetection:\n" + indent(detection) + strings.Join(extra, "\n")
	r, err := rule.Parse([]byte(src), "test.yml")
	if err != nil {
		return nil, nil, err
	}
	return Compile(r)
}

func indent(s string) string {
	var b strings.Builder
	for _, line := range strings.Split(strings.TrimRight(s, "\n"), "\n") {
		b.WriteString("  " + line + "\n")
	}
	return b.String()
}

func baseline(f Fields) Responses { return Responses{DefaultProbe: f} }

func TestModifiers(t *testing.T) {
	resp := baseline(Fields{
		"http.title":           "NKW — Autonomous Penetration Testing Console",
		"http.body":            "<html>\n<a href=\"/function/tasks\">tasks</a>\n</html>",
		"http.status_code":     200,
		"http.favicon.mmh3":    -576220750,
		"http.headers.server":  []any{"nginx", "envoy"},
		"tls.cert.san":         []any{"a.example", "b.example"},
		"tls.cert.self_signed": true,
		"service.banner":       "\x00\x01SSH-2.0-Go\r\n",
		"x-shodan.ip":          "10.1.2.3",
	})

	tests := []struct {
		sel  string
		want bool
	}{
		// exact match is case-insensitive and anchored
		{"http.title: 'nkw — autonomous penetration testing console'", true},
		{"http.title: 'Autonomous Penetration Testing Console'", false},
		{"http.title|cased: 'nkw — autonomous penetration testing console'", false},
		{"http.title|contains: 'penetration testing'", true},
		{"http.title|contains|cased: 'penetration testing'", false},
		{"http.title|startswith: 'nkw'", true},
		{"http.title|startswith: 'ARTEX'", false},
		{"http.title|endswith: 'CONSOLE'", true},
		// wildcards in plain values
		{"http.title: 'NKW*Console'", true},
		{"http.title: 'NK? —*'", true},
		{"http.title: 'NKW'", false},
		{`http.title|contains: 'Console\*'`, false},
		// contains crosses newlines
		{"http.body|contains: 'function/tasks'", true},
		{"http.body: '*function/tasks*'", true},
		// value lists are OR, |all makes them AND
		{"http.title|contains: ['ARTEX', 'NKW']", true},
		{"http.title|contains|all: ['ARTEX', 'NKW']", false},
		{"http.title|contains|all: ['Console', 'NKW']", true},
		// numbers
		{"http.status_code: 200", true},
		{"http.status_code: '200'", true},
		{"http.status_code|gte: 200", true},
		{"http.status_code|gt: 200", false},
		{"http.status_code|lt: 300", true},
		{"http.favicon.mmh3: -576220750", true},
		{"http.favicon.mmh3: 576220750", false},
		// lists in the response: any element
		{"http.headers.server: envoy", true},
		{"tls.cert.san|endswith: '.example'", true},
		{"tls.cert.self_signed: true", true},
		// re is used as written
		{"http.title|re: '^NKW\\s'", true},
		{"http.title|re: '^nkw\\s'", false},
		{"http.title|re: '(?i)^nkw\\s'", true},
		// hex for binary banners
		{"service.banner|hex|startswith: '0001'", true},
		{"service.banner|hex|contains: '5353482d322e30'", true},
		{"service.banner|hex: '0001'", false},
		// exists and null
		{"http.title|exists: true", true},
		{"ssh.banner|exists: true", false},
		{"ssh.banner|exists: false", true},
		{"ssh.banner: null", true},
		{"http.title: null", false},
		{"ssh.banner|contains: 'x'", false},
		// cidr
		{"x-shodan.ip|cidr: 10.0.0.0/8", true},
		{"x-shodan.ip|cidr: 192.168.0.0/16", false},
	}
	for _, tt := range tests {
		c, _, err := compileErr("sel:\n  " + tt.sel + "\ncondition: sel")
		if err != nil {
			t.Errorf("%s: %v", tt.sel, err)
			continue
		}
		if got := c.Eval(resp).Match; got != tt.want {
			t.Errorf("%s: match = %v, want %v", tt.sel, got, tt.want)
		}
	}
}

func TestSelectionShapes(t *testing.T) {
	resp := baseline(Fields{
		"http.title":       "Login",
		"http.body":        "Autonomous penetration testing platform",
		"http.headers_raw": "Server: nginx\r\nX-Powered-By: Express\r\n",
	})
	tests := []struct {
		det  string
		want bool
	}{
		// a map is AND
		{"sel:\n  http.title: login\n  http.body|contains: platform\ncondition: sel", true},
		{"sel:\n  http.title: login\n  http.body|contains: nope\ncondition: sel", false},
		// a list of maps is OR
		{"sel:\n  - http.title: nope\n  - http.body|contains: platform\ncondition: sel", true},
		// keywords search banner, raw headers and body, case-insensitively
		{"keywords:\n  - 'autonomous PENETRATION testing'\ncondition: keywords", true},
		{"keywords:\n  - 'x-powered-by: express'\ncondition: keywords", true},
		{"keywords:\n  - 'Login'\ncondition: keywords", false}, // title is not a keyword field
		{"keywords: 'platform'\ncondition: keywords", true},
	}
	for _, tt := range tests {
		c := compile(t, tt.det)
		if got := c.Eval(resp).Match; got != tt.want {
			t.Errorf("%q: match = %v, want %v", tt.det, got, tt.want)
		}
	}
}

func TestProbeBinding(t *testing.T) {
	c := compile(t,
		"sel_api:\n  probe: version_api\n  http.body|contains: ExamplePanel\nsel_page:\n  http.title: Example\ncondition: sel_api and sel_page",
		"probes:\n  version_api:\n    protocol: http\n    request:\n      method: GET\n      path: /api/version\n")

	page := Fields{"http.title": "Example"}
	if c.Eval(Responses{DefaultProbe: page}).Match {
		t.Error("matched without the version_api response")
	}
	api := Fields{"http.body": `{"product":"ExamplePanel"}`}
	if !c.Eval(Responses{DefaultProbe: page, "version_api": api}).Match {
		t.Error("no match with both responses")
	}
	// the API field must come from the API probe, not the baseline
	if c.Eval(Responses{DefaultProbe: Fields{"http.title": "Example", "http.body": "ExamplePanel"}}).Match {
		t.Error("baseline body satisfied a selection bound to version_api")
	}
}

func TestMatchedSelections(t *testing.T) {
	c := compile(t, "selection_title:\n  http.title|contains: Console\nselection_route:\n  http.body|contains: /function/tasks\nfilter:\n  http.title: nope\ncondition: selection_title and selection_route and not filter")
	res := c.Eval(baseline(Fields{"http.title": "Console", "http.body": "/function/tasks"}))
	if !res.Match || strings.Join(res.Matched, ",") != "selection_route,selection_title" {
		t.Errorf("got match=%v matched=%v", res.Match, res.Matched)
	}
}

// A condition that holds only through negation has no selection that held.
// Matched is then empty, not nil, so the JSON record has "matched":[].
func TestMatchedSelectionsEmpty(t *testing.T) {
	c := compile(t, "filter:\n  http.title: nope\ncondition: not filter")
	res := c.Eval(baseline(Fields{"http.title": "Console"}))
	if b, _ := json.Marshal(res.Matched); !res.Match || string(b) != "[]" {
		t.Errorf("got match=%v matched=%s, want true and []", res.Match, b)
	}
}

func TestExtract(t *testing.T) {
	c := compile(t, "sel:\n  http.title|contains: Console\ncondition: sel",
		"extract:",
		"  brand:",
		"    field: http.title",
		`    regex: '^(?P<brand>.+?)\s+[—–-]\s+Autonomous Penetration Testing Console'`,
		"  version:",
		"    field: http.body",
		"    jsonpath: $.build.version",
		"  first_group:",
		"    field: http.title",
		`    regex: '^(\w+)'`,
	)
	res := c.Eval(baseline(Fields{
		"http.title": "ARGOS – Autonomous Penetration Testing Console",
		"http.body":  `{"build":{"version":"1.4.2"}}`,
	}))
	want := map[string]string{"brand": "ARGOS", "version": "1.4.2", "first_group": "ARGOS"}
	for k, v := range want {
		if res.Extracted[k] != v {
			t.Errorf("extracted %s = %q, want %q", k, res.Extracted[k], v)
		}
	}

	// no extraction without a match
	if res := c.Eval(baseline(Fields{"http.title": "Other"})); res.Extracted != nil {
		t.Errorf("extracted on no_match: %v", res.Extracted)
	}
}

func TestCompileErrors(t *testing.T) {
	tests := []struct {
		det   string
		extra string
		want  string
	}{
		{"sel:\n  http.title: x", "", "missing condition"},
		{"sel:\n  http.title: x\ncondition: other", "", "unknown selection"},
		{"sel:\n  http.titel: x\ncondition: sel", "", "unknown field"},
		{"sel:\n  http.headers.Server: x\ncondition: sel", "", "unknown field"},
		{"sel:\n  http.title|wildcard: x\ncondition: sel", "", "unknown modifier"},
		{"sel:\n  http.title|contains|startswith: x\ncondition: sel", "", "can't be combined"},
		{"sel:\n  http.status_code|gt: abc\ncondition: sel", "", "needs a number"},
		{"sel:\n  http.title|re: '(unclosed'\ncondition: sel", "", "missing closing"},
		{"sel:\n  http.title|exists: yes please\ncondition: sel", "", "exists takes true or false"},
		{"sel:\n  service.banner|hex: zz\ncondition: sel", "", "invalid hex"},
		{"sel:\n  probe: missing\n  http.title: x\ncondition: sel", "", "not declared"},
		{"sel:\n  http.title: []\ncondition: sel", "", "empty value list"},
		{"sel:\n  - http.title: x\n  - plain\ncondition: sel", "", "can't also contain plain values"},
		{"sel:\n  http.title: x\ncondition: sel", "extract:\n  v:\n    field: http.title\n", "needs a regex or a jsonpath"},
		{"sel:\n  http.title: x\ncondition: sel", "extract:\n  v:\n    field: http.body\n    jsonpath: $.a[0]\n", "only dotted paths"},
	}
	for _, tt := range tests {
		_, _, err := compileErr(tt.det, tt.extra)
		if err == nil || !strings.Contains(err.Error(), tt.want) {
			t.Errorf("%q: got error %v, want one containing %q", tt.det, err, tt.want)
		}
	}
}

func TestUnusedSelectionWarning(t *testing.T) {
	_, warnings, err := compileErr("sel:\n  http.title: x\nfilter:\n  http.body: y\ncondition: sel")
	if err != nil {
		t.Fatal(err)
	}
	if len(warnings) != 1 || !strings.Contains(warnings[0].Msg, `"filter"`) {
		t.Errorf("warnings = %v", warnings)
	}
}

// Tests give custom probe responses under probes, by probe id. A probe a
// test doesn't list got no response.
func TestRunTestsCustomProbes(t *testing.T) {
	c := compile(t, "sel:\n  probe: css\n  http.body.sha256: ab12\ncondition: sel",
		"probes:",
		"  css: { protocol: http, request: { path: /app.css } }",
		"tests:",
		"  - name: file has the hash",
		"    expect: match",
		"    probes: { css: { http.body.sha256: ab12 } }",
		"  - name: baseline body is not the file",
		"    expect: match",
		"    response: { http.body.sha256: ab12 }",
		"  - name: no response from the probe",
		"    expect: no_match",
		"    response: { http.title: Console }",
		"  - name: unknown field in a probe response",
		"    expect: match",
		"    probes: { css: { http.sha256: ab12 } }",
	)
	want := []bool{true, false, true, false}
	for i, r := range c.RunTests() {
		if r.Passed != want[i] {
			t.Errorf("test %q: passed = %v, want %v (%s)", r.Name, r.Passed, want[i], r.Detail)
		}
	}
}

func TestRunTests(t *testing.T) {
	c := compile(t, "sel:\n  http.title|contains: Console\ncondition: sel",
		"extract:",
		"  brand:",
		"    field: http.title",
		`    regex: '^(?P<brand>\w+)'`,
		"tests:",
		"  - name: pass",
		"    expect: match",
		"    extracted: { brand: NKW }",
		"    response: { http.title: 'NKW Console' }",
		"  - name: wrong expectation",
		"    expect: no_match",
		"    response: { http.title: 'NKW Console' }",
		"  - name: wrong extraction",
		"    expect: match",
		"    extracted: { brand: ARTEX }",
		"    response: { http.title: 'NKW Console' }",
		"  - name: unknown field",
		"    expect: match",
		"    response: { http.titel: 'NKW Console' }",
	)
	res := c.RunTests()
	want := []bool{true, false, false, false}
	if len(res) != len(want) {
		t.Fatalf("got %d results, want %d", len(res), len(want))
	}
	for i, r := range res {
		if r.Passed != want[i] {
			t.Errorf("test %q: passed = %v, want %v (%s)", r.Name, r.Passed, want[i], r.Detail)
		}
	}
}
