package convert

import (
	"regexp"
	"strings"
	"testing"

	"go.yaml.in/yaml/v3"
)

func nucleiFor(t *testing.T, detection string) Result {
	t.Helper()
	res, err := Convert(ruleFrom(t, detection), "nuclei")
	if err != nil {
		t.Fatal(err)
	}
	if res.Template != "" {
		var doc map[string]any
		if err := yaml.Unmarshal([]byte(res.Template), &doc); err != nil {
			t.Fatalf("template is not YAML: %v\n%s", err, res.Template)
		}
	}
	return res
}

func wantIn(t *testing.T, res Result, parts ...string) {
	t.Helper()
	for _, p := range parts {
		if !strings.Contains(res.Template, p) {
			t.Errorf("template lacks %q:\n%s", p, res.Template)
		}
	}
}

func TestNucleiTitleAndBody(t *testing.T) {
	res := nucleiFor(t, specFamily)
	if res.Fidelity != Exact || res.TemplateID != "athar-t" {
		t.Errorf("fidelity %s, id %q", res.Fidelity, res.TemplateID)
	}
	wantIn(t, res,
		"id: athar-t\n",
		"variables:\n  title: \"\"\n",
		"- '{{RootURL}}/'",
		`contains(tolower(title), "autonomous penetration testing console") && contains(tolower(body), "/function/tasks")`,
		"name: title\n        internal: true",
		"# Fidelity: exact\n",
	)
	if strings.Contains(res.Template, "req-condition") {
		t.Error("one request needs no req-condition")
	}
}

func TestNucleiFaviconAddsRequest(t *testing.T) {
	res := nucleiFor(t, specVariant)
	if res.Fidelity != Approximate {
		t.Errorf("fidelity %s, want approximate (favicon path)", res.Fidelity)
	}
	wantIn(t, res,
		"'{{RootURL}}/favicon.ico'",
		"req-condition: true",
		"stop-at-first-match: true",
		`status_code_2 > 0 && (`,
		`starts_with(tolower(title_2), "artex")`,
		`(status_code_1 == 200 && mmh3(base64_py(body_1)) == "-576220750")`,
		"name: title_2",
		"- '{{RootURL}}/favicon.ico'\n      - '{{RootURL}}/'",
	)
}

func TestNucleiNegatedHeaderGetsDefault(t *testing.T) {
	res := nucleiFor(t, `
selection:
  http.title: 'Console'
filter:
  http.headers.x-powered-by|startswith: 'nginx'
condition: selection and not filter
`)
	wantIn(t, res,
		`tolower(title) == "console" && !starts_with(tolower(x_powered_by), "nginx")`,
		"x_powered_by: \"\"",
	)
}

func TestNucleiCertificateOnly(t *testing.T) {
	res := nucleiFor(t, `
selection:
  tls.cert.issuer.cn: 'PentAGI CA'
  tls.cert.san|endswith: '.nip.io'
condition: selection
`)
	if res.Fidelity != Approximate {
		t.Errorf("fidelity %s, want approximate (SANs)", res.Fidelity)
	}
	wantIn(t, res, "ssl:\n  - address: '{{Host}}:{{Port}}'\n    matchers:")
	var doc struct {
		SSL []struct{ Matchers []struct{ DSL []string } }
	}
	if err := yaml.Unmarshal([]byte(res.Template), &doc); err != nil || len(doc.SSL) != 1 || len(doc.SSL[0].Matchers) != 1 {
		t.Fatalf("ssl block: %v\n%s", err, res.Template)
	}
	// SANs go one per line, split by a real newline: Nuclei's DSL reads
	// the two characters \n as n.
	want := `tolower(issuer_cn) == "pentagi ca" && regex("(?mi)\\.nip\\.io$", replace(trim_suffix(trim_prefix(to_string(subject_an), "["), "]"), " ", "` + "\n" + `"))`
	if got := doc.SSL[0].Matchers[0].DSL[0]; got != want {
		t.Errorf("dsl:\n got %q\nwant %q", got, want)
	}
	if strings.Contains(res.Template, "http:") || strings.Contains(res.Template, "variables:") {
		t.Errorf("certificate-only rule needs no http block or defaults:\n%s", res.Template)
	}
}

func TestNucleiCertificateAndPage(t *testing.T) {
	res := nucleiFor(t, `
selection_title:
  http.title|contains: 'Console'
selection_cert:
  tls.cert.subject.cn: 'acme'
condition: selection_title or selection_cert
`)
	wantIn(t, res,
		"ssl_subject_cn: \"\"",
		"ssl:\n  - address: '{{Host}}:{{Port}}'\nhttp:",
		`contains(tolower(title), "console") || tolower(ssl_subject_cn) == "acme"`,
	)
}

func TestNucleiCustomProbe(t *testing.T) {
	res := nucleiFor(t, `
selection:
  probe: api
  http.body|contains: '"status":"ok"'
condition: selection
`)
	wantIn(t, res,
		"'{{RootURL}}/api'",
		`contains(tolower(body), "\"status\":\"ok\"")`,
		"# Note: sends 1 custom probe request; athar scan sends custom probes only with -probes\n",
	)
	if strings.Contains(res.Template, "{{RootURL}}/'") {
		t.Error("the baseline request is not read, so it should not be sent")
	}
}

func TestNucleiQuoting(t *testing.T) {
	res := nucleiFor(t, `
selection:
  http.body|contains|cased: 'say "hi" \ now'
  http.title|re: '^v\d+\.\d+$'
condition: selection
`)
	wantIn(t, res, `contains(body, "say \"hi\" \\ now")`, `regex("^v\\d+\\.\\d+$", title)`)
}

// nucleiHTTP0 parses the template's first http block.
func nucleiHTTP0(t *testing.T, res Result) nucleiHTTP {
	t.Helper()
	var doc nucleiTemplate
	if err := yaml.Unmarshal([]byte(res.Template), &doc); err != nil || len(doc.HTTP) != 1 {
		t.Fatalf("http block: %v\n%s", err, res.Template)
	}
	return doc.HTTP[0]
}

// Nuclei expands {{…}} in a DSL expression, and refuses one with a pair of
// percent-encoded braces. A rule value must reach the matcher as text.
func TestNucleiTemplateMarkersInValues(t *testing.T) {
	res := nucleiFor(t, `
selection:
  http.body|contains: '{{ message }}'
  http.title|contains|cased: '{{{Hostname}}'
  http.headers.server|re: '^a{{b}}\{{$'
  http.headers_raw|contains: 'x=%7B%7Bhost%7D%7D{%7b%7|'
condition: selection
`)
	if res.Fidelity != Exact {
		t.Errorf("fidelity %s, want exact", res.Fidelity)
	}
	dsl := nucleiHTTP0(t, res).Matchers[0].DSL[0]
	for _, want := range []string{
		`contains(tolower(body), "{\{ message }}")`,
		`contains(title, "{\{\{Hostname}}")`,
		`regex("^a{\{b}}\\{\{$", server)`,
		`contains(tolower(header), "x=%7b\%7bhost%7d%7d{\%7b\%7|")`,
	} {
		if !strings.Contains(dsl, want) {
			t.Errorf("dsl lacks %s:\n%s", want, dsl)
		}
	}
	if nucleiMarked(dsl) {
		t.Errorf("nuclei would expand a marker in:\n%s", dsl)
	}
}

func TestNucleiTemplateMarkersInExtract(t *testing.T) {
	r := parse(t, "t.yml", `
title: t
detection:
  selection:
    http.status_code: 200
  condition: selection
extract:
  app:
    field: http.body
    regex: 'id={{randstr}} (\w+)'
`)
	res, err := Convert(r, nucleiTarget)
	if err != nil {
		t.Fatal(err)
	}
	x := nucleiHTTP0(t, res).Extractors
	if len(x) != 1 || len(x[0].Regex) != 1 || x[0].Group != 1 {
		t.Fatalf("extractors: %+v", x)
	}
	if got, want := x[0].Regex[0], `id=\x7B{randstr}} (\w+)`; got != want {
		t.Errorf("regex %q, want %q", got, want)
	}
}

// The rewritten pattern must match what the rule's pattern matches.
func TestNucleiRegexBraces(t *testing.T) {
	for _, tc := range []struct{ re, want, text string }{
		{`a{2}b{`, `a{2}b{`, "aab{"},
		{`{{x}}`, `\x7B{x}}`, "{{x}}"},
		{`{{{x`, `\x7B\x7B{x`, "{{{x"},
		{`\{{x`, `\x7B{x`, "{{x"},
		{`\\{{x`, `\\\x7B{x`, `\{{x`},
		{`x{{2}y`, `x\x7B{2}y`, "x{{y"},
		{`[{{]+$`, `[\x7B{]+$`, "{{{"},
		{`\Q{{a}}\E+`, `\Q{\E\Q{a}}\E+`, "{{a}}}"},
		{`\Qa\E{{`, `\Qa\E\x7B{`, "a{{"},
		{`\Q{{`, `\Q{\E\Q{`, "{{"},
	} {
		got := reBraces(tc.re)
		if got != tc.want {
			t.Errorf("reBraces(%q) = %q, want %q", tc.re, got, tc.want)
		}
		if strings.Contains(got, "{{") {
			t.Errorf("reBraces(%q) = %q still has {{", tc.re, got)
		}
		for _, re := range []string{tc.re, got} {
			if m := regexp.MustCompile(re).FindString(tc.text); m != tc.text {
				t.Errorf("%q finds %q in %q", re, m, tc.text)
			}
		}
	}
}

// Nuclei would expand markers in a request, so a probe that has one in its
// path or headers is not converted.
func TestNucleiTemplateMarkersInProbe(t *testing.T) {
	for _, request := range []string{
		`{ path: '/a{{Hostname}}' }`,
		`{ path: '/a%7B%7bx' }`,
		`{ path: '/a§Hostname§' }`,
		`{ path: /a, headers: { X-Trace: '{{randstr}}' } }`,
	} {
		r := parse(t, "t.yml", `
title: t
probes:
  p: { protocol: http, request: `+request+` }
detection:
  selection:
    http.title: 'Console'
  selection_probe:
    probe: p
    http.status_code: 200
  condition: selection and selection_probe
`)
		res, err := Convert(r, nucleiTarget)
		if err != nil {
			t.Fatal(err)
		}
		if res.Fidelity != Superset || len(res.Notes) == 0 || !strings.Contains(res.Notes[0], "nuclei would expand") {
			t.Errorf("%s: fidelity %s, notes %q", request, res.Fidelity, res.Notes)
		}
		if strings.Contains(res.Template, "/a") {
			t.Errorf("%s: the probe is still requested:\n%s", request, res.Template)
		}
	}
}

// Text from the rule must not end a comment line: the rest would be YAML.
func TestNucleiCommentsStayComments(t *testing.T) {
	for _, tc := range []struct{ author, want string }{
		{`"Jane Doe\n"`, "# Rule by Jane Doe, licensed under the Detection Rule License 1.1:\n"},
		{`"Jane\nflow: http(1)\r\nvariables: {a: b}"`, "# Rule by Jane flow: http(1)  variables: {a: b}, licensed"},
		{`"Jane\u2028id: x\u2029id: y\u0085id: z"`, "# Rule by Jane id: x id: y id: z, licensed"},
	} {
		r := parse(t, "a\nflow: b.yml", `
title: t
id: "1\nflow: c"
author: `+tc.author+`
detection:
  selection:
    http.title: 'Console'
    "service.banner\nflow: d": 'x'
  condition: selection
extract:
  "v\nflow: e":
    field: "service.banner\nflow: f"
    regex: 'x'
`)
		res, err := Convert(r, nucleiTarget)
		if err != nil {
			t.Fatal(err)
		}
		wantIn(t, res, tc.want, "# Converted by athar convert from a flow: b.yml (Athar rule 1 flow: c).\n")
		head, _, ok := strings.Cut(res.Template, "\nid: ")
		if !ok {
			t.Fatalf("no id:\n%s", res.Template)
		}
		for _, line := range regexp.MustCompile(`[\r\n\x{85}\x{2028}\x{2029}]`).Split(head, -1) {
			if !strings.HasPrefix(line, "# ") {
				t.Errorf("not a comment: %q", line)
			}
		}
		var doc map[string]any
		if err := yaml.Unmarshal([]byte(res.Template), &doc); err != nil {
			t.Fatal(err)
		}
		for k := range doc {
			if k != "id" && k != "info" && k != "variables" && k != "http" {
				t.Errorf("top-level key %q", k)
			}
		}
	}
}

// Probe ids are free text; none may be taken for the baseline, the favicon
// request or the ssl block, and no two may share a request.
func TestNucleiProbeIDs(t *testing.T) {
	r := parse(t, "t.yml", `
title: t
probes:
  ssl: { protocol: http, request: { path: /p-ssl } }
  api/v1: { protocol: http, request: { path: /p-slash } }
  api: { protocol: http, request: { path: /p-api } }
  "#favicon": { protocol: http, request: { path: /p-favicon } }
  "a\0b\x01c": { protocol: http, request: { path: /p-control } }
detection:
  s1: { probe: ssl, http.title|contains: 'one' }
  s2: { probe: api/v1, http.title|contains: 'two' }
  s3: { probe: api, http.title|contains: 'three' }
  s4: { probe: '#favicon', http.title|contains: 'four' }
  s5: { probe: "a\0b\x01c", http.title|contains: 'five' }
  s6: { http.favicon.mmh3: 1 }
  condition: all of s*
`)
	res, err := Convert(r, nucleiTarget)
	if err != nil {
		t.Fatal(err)
	}
	if res.Fidelity != Approximate {
		t.Errorf("fidelity %s, want approximate (favicon path)", res.Fidelity)
	}
	if strings.Contains(res.Template, "\nssl:") {
		t.Errorf("a probe named ssl is not the ssl block:\n%s", res.Template)
	}
	h := nucleiHTTP0(t, res)
	want := []string{"{{RootURL}}/favicon.ico", "{{RootURL}}/p-favicon", "{{RootURL}}/p-control", "{{RootURL}}/p-api", "{{RootURL}}/p-slash", "{{RootURL}}/p-ssl"}
	if strings.Join(h.Path, " ") != strings.Join(want, " ") {
		t.Errorf("paths %q, want %q", h.Path, want)
	}
	wantDSL := `status_code_6 > 0 && (contains(tolower(title_6), "one") && contains(tolower(title_5), "two") && contains(tolower(title_4), "three")` +
		` && contains(tolower(title_2), "four") && contains(tolower(title_3), "five") && (status_code_1 == 200 && mmh3(base64_py(body_1)) == "1"))`
	if got := h.Matchers[0].DSL[0]; got != wantDSL {
		t.Errorf("dsl:\n got %s\nwant %s", got, wantDSL)
	}
	wantIn(t, res, "# Note: sends 5 custom probe requests;")
}

func TestNucleiDropsWhatItCannotRead(t *testing.T) {
	res := nucleiFor(t, `
selection:
  http.title|contains: 'Console'
  service.banner|contains: 'SSH-2.0'
condition: selection
`)
	if res.Fidelity != Superset || len(res.Notes) == 0 || !strings.Contains(res.Notes[0], "service.banner") {
		t.Errorf("fidelity %s, notes %q", res.Fidelity, res.Notes)
	}
	res = nucleiFor(t, `
selection:
  service.banner|contains: 'SSH-2.0'
condition: selection
`)
	if res.Fidelity != Unsupported || res.Template != "" {
		t.Errorf("banner only: fidelity %s, template %q", res.Fidelity, res.Template)
	}
}
