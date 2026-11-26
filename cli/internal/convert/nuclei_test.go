package convert

import (
	"regexp"
	"strings"
	"testing"

	"go.yaml.in/yaml/v3"

	"github.com/Athar-HQ/Athar/cli/internal/eval"
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

// dslOf returns the template's matcher expression.
func dslOf(t *testing.T, res Result) string {
	t.Helper()
	type block struct{ Matchers []struct{ DSL []string } }
	var doc struct{ SSL, HTTP []block }
	if err := yaml.Unmarshal([]byte(res.Template), &doc); err != nil {
		t.Fatalf("template is not YAML: %v\n%s", err, res.Template)
	}
	for _, b := range append(doc.HTTP, doc.SSL...) {
		for _, m := range b.Matchers {
			if len(m.DSL) == 1 {
				return m.DSL[0]
			}
		}
	}
	t.Fatalf("no matcher:\n%s", res.Template)
	return ""
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
		"- '{{RootURL}}/'",
		`regex("(?is)Autonomous Penetration Testing Console", trim_prefix(title, "=")) && regex("(?is)/function/tasks", body)`,
		"name: title\n        internal: true",
		`? "=" + trim_space(`, `: "="'`,
		"# Fidelity: exact\n",
	)
	if strings.Contains(res.Template, "req-condition") {
		t.Error("one request needs no req-condition")
	}
	// A cluster of templates only gets the variables of its first one.
	if strings.Contains(res.Template, "variables:") {
		t.Errorf("the title must not need a default under variables:\n%s", res.Template)
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
		`starts_with(tolower(trim_prefix(title_2, "=")), "artex")`,
		`(status_code_1 == 200 && mmh3(base64_py(body_1)) == "-576220750")`,
		"name: title_2",
		"- '{{RootURL}}/favicon.ico'\n      - '{{RootURL}}/'",
	)
}

func TestNucleiNegatedHeader(t *testing.T) {
	res := nucleiFor(t, `
selection:
  http.title: 'Console'
filter:
  http.headers.x-powered-by|startswith: 'nginx'
condition: selection and not filter
`)
	wantIn(t, res, `regex("(?is)^Console$", trim_prefix(title, "=")) && !regex("(?mi)^x-powered-by: nginx", header)`)
	if res.Fidelity != Exact || strings.Contains(res.Template, "variables:") {
		t.Errorf("fidelity %s; a header must not need a default under variables:\n%s", res.Fidelity, res.Template)
	}
}

// An absent field fails every comparison in the scanner, also one that
// holds for an empty value, and exists tells the two apart.
func TestNucleiAbsentFields(t *testing.T) {
	hasTitle := `regex("(?is)<title[^>]*>.*?</title>", body)`
	for _, c := range []struct{ detection, want string }{
		{"selection:\n  http.title|re: '^$'\ncondition: selection",
			`(` + hasTitle + ` && regex("^$", trim_prefix(title, "=")))`},
		{"selection:\n  http.status_code: 302\nfilter:\n  http.title: ''\ncondition: selection and not filter",
			`status_code == 302 && !(` + hasTitle + ` && tolower(trim_prefix(title, "=")) == "")`},
		{"selection:\n  http.title: '*'\ncondition: selection",
			`(` + hasTitle + ` && regex("(?is)^.*$", trim_prefix(title, "=")))`},
		// No test where the comparison fails for an empty value anyway.
		{"selection:\n  http.status_code: 302\nfilter:\n  http.title|contains: 'zzz'\ncondition: selection and not filter",
			`status_code == 302 && !contains(tolower(trim_prefix(title, "=")), "zzz")`},
		{"selection:\n  http.title|exists: true\ncondition: selection", hasTitle},
		{"selection:\n  http.title|exists: false\n  http.body|contains: 'x'\ncondition: selection",
			`contains(tolower(body), "x") && !(` + hasTitle + `)`},
		{"selection:\n  http.status_code: 200\nfilter:\n  http.title|exists: false\ncondition: selection and not filter",
			`status_code == 200 && ` + hasTitle},
		{"selection:\n  http.headers.x-here|exists: true\n  http.headers.x-gone: null\ncondition: selection",
			`!(regex("(?mi)^x-gone:", header)) && regex("(?mi)^x-here:", header)`},
		{"selection:\n  http.favicon.md5|exists: true\ncondition: selection", `(status_code == 200 && len(body) > 0)`},
		// Nuclei's hash of an empty answer, which is no favicon.
		{"selection:\n  http.favicon.sha256: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855\ncondition: selection",
			`(status_code == 200 && len(body) > 0 && sha256(body) == "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")`},
		// An ssl block leaves an empty certificate field undefined, so its
		// name is only read behind a test for it.
		{"selection:\n  tls.cert.subject.cn|exists: true\nfilter:\n  tls.cert.issuer.cn|contains|cased: 'Evil'\ncondition: selection and not filter",
			`contains(response, "\"subject_cn\":") && !(contains(response, "\"issuer_cn\":") && contains(issuer_cn, "Evil"))`},
		{"selection:\n  http.body|contains: 'x'\nfilter:\n  tls.cert.subject.cn|re: '^$'\ncondition: selection and not filter",
			`contains(tolower(body), "x") && !(to_string(ssl_subject_cn) != "" && regex("^$", ssl_subject_cn))`},
	} {
		res := nucleiFor(t, c.detection)
		if got := dslOf(t, res); got != c.want || res.Fidelity == Superset {
			t.Errorf("%s (%s):\n got %s\nwant %s", c.detection, res.Fidelity, got, c.want)
		}
	}
}

// Every value of a repeated header has its own line in the header block, so
// a comparison can look at one value, as the scanner does.
func TestNucleiHeaderValues(t *testing.T) {
	for _, c := range []struct {
		field, value, want string
		fid                Fidelity
	}{
		{"http.headers.x-multi", `'two'`, `regex("(?mi)^x-multi: two\\r?$", header)`, Exact},
		{"http.headers.x-multi|contains", `'w'`, `regex("(?mi)^x-multi: .*w", header)`, Exact},
		{"http.headers.set-cookie|startswith", `'session='`, `regex("(?mi)^set-cookie: session=", header)`, Exact},
		{"http.headers.x-multi|endswith", `'o'`, `regex("(?mi)^x-multi: .*o\\r?$", header)`, Exact},
		{"http.headers.x-multi|contains|cased", `'Tw'`, `regex("(?m)^(?i:x-multi): .*Tw", header)`, Exact},
		{"http.headers.x-multi", `'t?o*'`, `regex("(?mi)^x-multi: t[^\\r\\n]o[^\\r\\n]*\\r?$", header)`, Exact},
		{"http.headers.x-multi|re", `'^T.o$'`, `regex("(?m)^(?i:x-multi): (?:(?:T[^\\n\\r]o)\\r?$)", header)`, Exact},
		{"http.headers.x-multi|re", `'a$|^b'`, `regex("(?m)^(?i:x-multi): (?:.*?(?:a)\\r?$|(?:b))", header)`, Exact},
		// An anchor in the middle can't be moved to the end of a line.
		{"http.headers.x-multi|re", `'(^|,)two'`, `(regex("(?mi)^x-multi:", header) && regex("(^|,)two", x_multi))`, Approximate},
		{"http.headers.transfer-encoding", `'chunked'`, `regex("(?mi)^transfer-encoding: chunked\\r?$", header)`, Approximate},
	} {
		res := nucleiFor(t, "selection:\n  "+c.field+": "+c.value+"\ncondition: selection")
		if got := dslOf(t, res); got != c.want {
			t.Errorf("%s: %s:\n got %s\nwant %s", c.field, c.value, got, c.want)
		}
		if res.Fidelity != c.fid || (c.fid == Approximate) != (len(res.Notes) == 1) {
			t.Errorf("%s: %s: fidelity %s, notes %q; want %s", c.field, c.value, res.Fidelity, res.Notes, c.fid)
		}
		if strings.Contains(res.Template, "variables:") {
			t.Errorf("%s: a header must not need a default under variables:\n%s", c.field, res.Template)
		}
	}
}

// headerRegexp must find a header block in which one value of the header
// satisfies the condition, and no other: the evaluator decides.
func TestHeaderRegexpMatchesPerValue(t *testing.T) {
	blocks := [][]string{
		nil, {""}, {"two"}, {"Two"}, {"one", "two"}, {"one two"}, {"two", "one"}, {"twoo", "ttwo"}, {"a,two"},
		{"tw", "o"}, {"T.o"}, {"x two y"}, {"two "}, {"tWo", "b"}, {"ab", "ba"}, {"session=1; Path=/", "a=1"},
	}
	for _, cond := range []string{
		"http.headers.x-test: 'two'", "http.headers.x-test: ''", "http.headers.x-test|cased: 'Two'",
		"http.headers.x-test|contains: 'wo'", "http.headers.x-test|contains: 'e t'", "http.headers.x-test|contains|cased: 'W'",
		"http.headers.x-test|startswith: 'tw'", "http.headers.x-test|endswith: 'o'", "http.headers.x-test|endswith|cased: 'O'",
		"http.headers.x-test: 't?o'", "http.headers.x-test: 't*'", "http.headers.x-test: '*o'", "http.headers.x-test: 'tw?'",
		"http.headers.x-test|contains: 'w?'", "http.headers.x-test|startswith: '?w'", "http.headers.x-test: 'T.o'",
		"http.headers.x-test|re: '^two$'", "http.headers.x-test|re: 'two'", "http.headers.x-test|re: '^t'", "http.headers.x-test|re: 'o$'",
		"http.headers.x-test|re: '^$'", "http.headers.x-test|re: '.'", "http.headers.x-test|re: '^.{3}$'", "http.headers.x-test|re: '(?i)^TWO$'",
		"http.headers.x-test|re: '^[^x]+$'", "http.headers.x-test|re: '\\s'", "http.headers.x-test|re: '^\\S*$'", "http.headers.x-test|re: 'o\\b'",
		"http.headers.x-test|re: 'a$|^b'", "http.headers.x-test|re: '^(one|two)$'", "http.headers.x-test|re: '(?s)^t.*o$'",
		"http.headers.x-test|re: '^t\\D+$'", "http.headers.x-test|re: 'two\\z'", "http.headers.x-test|re: '\\Atw'", "http.headers.x-test|re: 'x*'",
		"http.headers.x-test|re: '(?m)^two$'", "http.headers.x-test|re: '[\\x00-\\x{10FFFF}]{4}'", "http.headers.x-test|re: '^session=\\d+;'",
	} {
		r := ruleFrom(t, "selection:\n  "+cond+"\ncondition: selection")
		c, _, err := eval.Compile(r)
		if err != nil {
			t.Fatal(err)
		}
		e, err := build(r)
		if err != nil {
			t.Fatal(err)
		}
		pat, why := headerRegexp(nnf(e, false).(term), "x-test")
		if pat == "" {
			t.Errorf("%s: no expression: %s", cond, why)
			continue
		}
		re, err := regexp.Compile(pat)
		if err != nil {
			t.Errorf("%s: %v", cond, err)
			continue
		}
		for _, values := range blocks {
			block := "HTTP/1.1 200 OK\r\nServer: two\r\nX-Test-Two: two\r\n"
			f := eval.Fields{"http.headers.server": "two", "http.headers.x-test-two": "two"}
			list := make([]any, len(values))
			for i, v := range values {
				block += "X-Test: " + v + "\r\n"
				list[i] = v
			}
			switch len(values) {
			case 0:
			case 1:
				f["http.headers.x-test"] = values[0]
			default:
				f["http.headers.x-test"] = list
			}
			block += "Z-Last: tWo\r\n\r\n"
			want := c.Eval(eval.Responses{eval.DefaultProbe: f}).Match
			if got := re.MatchString(block); got != want {
				t.Errorf("%s on %q: %s gives %v, the evaluator %v", cond, values, pat, got, want)
			}
		}
	}
}

// tolower() is kept where it folds case as Go's (?i) does.
func TestNucleiCaseFolding(t *testing.T) {
	for s, want := range map[string]bool{
		"artex": true, "AutoCVE": true, "k": true, "K": true, "/_next/1.0?x=y": true, "自主渗透测试控制台": true, "ж": true,
		"i": false, "I": false, "s": false, "S": false, "Strix": false, "ΟΔΟΣ": false, "ς": false, "σ": false, "İ": false, "ſ": false, "д": false,
	} {
		if got := foldsAsLower(s); got != want {
			t.Errorf("foldsAsLower(%q) = %v, want %v", s, got, want)
		}
	}
	res := nucleiFor(t, `
selection:
  http.body|contains:
    - 'ΟΔΟΣ ΟΔΟΣ'
    - 'istanbul'
    - 'ARTEX'
  http.body|contains|cased: 'ΟΔΟΣ'
condition: selection
`)
	want := `(regex("(?is)ΟΔΟΣ ΟΔΟΣ", body) || regex("(?is)istanbul", body) || contains(tolower(body), "artex")) && contains(body, "ΟΔΟΣ")`
	if got := dslOf(t, res); got != want || res.Fidelity != Exact {
		t.Errorf("%s:\n got %s\nwant %s", res.Fidelity, got, want)
	}
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
	want := `(contains(response, "\"issuer_cn\":") && regex("(?is)^PentAGI CA$", issuer_cn)) && (contains(response, "\"subject_an\":") && regex("(?mi)\\.nip\\.io$", replace(trim_suffix(trim_prefix(to_string(subject_an), "["), "]"), " ", "` + "\n" + `")))`
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
		`regex("(?is)Console", trim_prefix(title, "=")) || (to_string(ssl_subject_cn) != "" && tolower(ssl_subject_cn) == "acme")`,
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
		`regex("(?is)\"status\":\"ok\"", body)`,
		"# Note: sends 1 custom probe request; athar scan sends custom probes only with -probes\n",
	)
	if strings.Contains(res.Template, "{{RootURL}}/'") {
		t.Error("the baseline request is not read, so it should not be sent")
	}
}

// athar scan hashes only a complete body; Nuclei hashes whatever it read.
func TestNucleiBodyHashIsApproximate(t *testing.T) {
	for _, field := range []string{"http.body.sha256: ff75", "http.body.mmh3: 123"} {
		res := nucleiFor(t, "selection:\n  "+field+"\ncondition: selection\n")
		if res.Fidelity != Approximate || len(res.Notes) != 1 || !strings.Contains(res.Notes[0], "cut short") {
			t.Errorf("%s: fidelity %s, notes %q", field, res.Fidelity, res.Notes)
		}
	}
}

func TestNucleiQuoting(t *testing.T) {
	res := nucleiFor(t, `
selection:
  http.body|contains|cased: 'say "hi" \ now'
  http.title|re: '^v\d+\.\d+$'
condition: selection
`)
	wantIn(t, res, `contains(body, "say \"hi\" \\ now")`, `regex("^v\\d+\\.\\d+$", trim_prefix(title, "="))`)
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
		// A value with s is compared with a regular expression, in which
		// every brace has a backslash of its own.
		`regex("(?is)\\{\\{ message \\}\\}", body)`,
		`contains(trim_prefix(title, "="), "{\{\{Hostname}}")`,
		`regex("(?m)^(?i:server): (?:(?:a\\{\\{b\\}\\}\\{\\{)\\r?$)", header)`,
		`regex("(?is)x=%7B\%7Bhost%7D%7D\\{\%7b%7\\|", header)`,
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
	wantDSL := `status_code_6 > 0 && (contains(tolower(trim_prefix(title_6, "=")), "one") && contains(tolower(trim_prefix(title_5, "=")), "two") && contains(tolower(trim_prefix(title_4, "=")), "three")` +
		` && contains(tolower(trim_prefix(title_2, "=")), "four") && regex("(?is)five", trim_prefix(title_3, "=")) && (status_code_1 == 200 && mmh3(base64_py(body_1)) == "1"))`
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

// target.tls limits a template to one scheme. A template that only reads the
// certificate needs no guard: its ssl block only matches over TLS.
func TestNucleiTargetTLS(t *testing.T) {
	title := "selection:\n  http.title: 'Console'\ncondition: selection\n"
	cert := "selection:\n  tls.cert.subject.cn: 'acme'\ncondition: selection\n"
	both := "a:\n  http.title: 'Console'\nb:\n  tls.cert.subject.cn: 'acme'\ncondition: a or b\n"
	with := func(detection, tls string) Result {
		t.Helper()
		r := ruleFrom(t, detection)
		r.Target.TLS = tls
		res, err := Convert(r, "nuclei")
		if err != nil {
			t.Fatal(err)
		}
		return res
	}
	auto := with(title, "auto")
	if strings.Contains(auto.Template, "Scheme") {
		t.Errorf("tls: auto needs no guard:\n%s", auto.Template)
	}
	if res := with(title, ""); res.Template != auto.Template {
		t.Errorf("no target.tls should convert like auto:\n%s", res.Template)
	}
	for _, c := range []struct {
		detection, tls, dsl string
	}{
		{title, "required", `Scheme == "https" && (regex("(?is)^Console$", trim_prefix(title, "=")))`},
		{title, "none", `Scheme == "http" && (regex("(?is)^Console$", trim_prefix(title, "=")))`},
		{specVariant, "required", `Scheme == "https" && status_code_2 > 0 && (regex(`},
		{both, "required", `Scheme == "https" && (regex("(?is)^Console$", trim_prefix(title, "=")) || (to_string(ssl_subject_cn) != "" && tolower(ssl_subject_cn) == "acme"))`},
		{both, "none", `Scheme == "http" && (regex("(?is)^Console$", trim_prefix(title, "=")) || (to_string(ssl_subject_cn) != "" && tolower(ssl_subject_cn) == "acme"))`},
	} {
		res := with(c.detection, c.tls)
		wantIn(t, res, c.dsl)
		if want := with(c.detection, "auto").Fidelity; res.Fidelity != want {
			t.Errorf("tls: %s: fidelity %s, want %s as for auto", c.tls, res.Fidelity, want)
		}
	}
	if res := with(cert, "required"); res.Template != with(cert, "auto").Template {
		t.Errorf("a certificate-only template needs no guard:\n%s", res.Template)
	}
	// A plaintext service has no certificate to read.
	if res := with(cert, "none"); res.Fidelity != Unsupported || res.Template != "" || len(res.Notes) != 1 || !strings.Contains(res.Notes[0], "target.tls") {
		t.Errorf("certificate only, tls: none: fidelity %s, notes %q, template %q", res.Fidelity, res.Notes, res.Template)
	}
}

// The scanner matches headers as received. Nuclei's header block comes from
// Go's net/http, which rewrites a few of them, and from a request for gzip.
func TestNucleiHeadersNetHTTPRewrites(t *testing.T) {
	for _, name := range []string{"transfer-encoding", "connection", "trailer", "content-length", "content-encoding", "cache-control"} {
		res := nucleiFor(t, "selection:\n  http.headers."+name+"|contains: 'x'\ncondition: selection\n")
		if res.Fidelity != Approximate || len(res.Notes) != 1 || !strings.Contains(res.Notes[0], "header block") {
			t.Errorf("%s: fidelity %s, notes %q", name, res.Fidelity, res.Notes)
		}
		wantIn(t, res, `regex("(?mi)^`+name+`: .*x", header)`)
	}
	// Their variables can be undefined while the block has the header, so
	// an expression that needs the variable is left out.
	res := nucleiFor(t, "selection:\n  http.title|contains: 'x'\n  http.headers.connection|re: '(^|,)close'\ncondition: selection\n")
	if res.Fidelity != Superset || strings.Contains(dslOf(t, res), "connection") {
		t.Errorf("connection|re: fidelity %s:\n%s", res.Fidelity, res.Template)
	}
	if res = nucleiFor(t, "selection:\n  http.headers.server|contains: 'x'\ncondition: selection\n"); res.Fidelity != Exact {
		t.Errorf("server: fidelity %s, notes %q", res.Fidelity, res.Notes)
	}
}
