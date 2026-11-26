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

func TestNucleiQuoting(t *testing.T) {
	res := nucleiFor(t, `
selection:
  http.body|contains|cased: 'say "hi" \ now'
  http.title|re: '^v\d+\.\d+$'
condition: selection
`)
	wantIn(t, res, `contains(body, "say \"hi\" \\ now")`, `regex("^v\\d+\\.\\d+$", trim_prefix(title, "="))`)
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
