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
