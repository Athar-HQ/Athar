package convert

import (
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
		{title, "required", `Scheme == "https" && (tolower(title) == "console")`},
		{title, "none", `Scheme == "http" && (tolower(title) == "console")`},
		{specVariant, "required", `Scheme == "https" && status_code_2 > 0 && (contains(`},
		{both, "required", `Scheme == "https" && (tolower(title) == "console" || tolower(ssl_subject_cn) == "acme")`},
		{both, "none", `Scheme == "http" && (tolower(title) == "console" || tolower(ssl_subject_cn) == "acme")`},
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
