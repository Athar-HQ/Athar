package convert

import (
	"bufio"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/md5"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"html"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Athar-HQ/Athar/cli/internal/eval"
	"github.com/Athar-HQ/Athar/cli/internal/probe"
	"github.com/Athar-HQ/Athar/cli/internal/rule"
)

// These tests run the converted templates in Nuclei against local servers
// that answer like the rules' tests. They need the nuclei binary and are
// skipped without it, and with -short.

// TestNucleiTemplatesRun checks every rule in rules/. An exact template must
// give each test's expected result and extracted values; a superset one must
// at least find every match. Tests whose response can't be rebuilt from its
// fields (hashes of unknown files) are skipped.
func TestNucleiTemplatesRun(t *testing.T) {
	bin := nucleiBin(t)
	files, err := rule.Files([]string{"../../../rules"})
	if err != nil {
		t.Fatal(err)
	}
	var rules []*rule.Rule
	for _, f := range files {
		r, err := rule.Load(f)
		if err != nil {
			t.Fatal(err)
		}
		rules = append(rules, r)
	}
	nucleiCheck(t, bin, rules, nil, false)
}

// TestNucleiTemplateFeatures checks conversions the repository's rules don't
// use yet, strictly: approximate templates must also give the expected
// result here.
//
// Nuclei runs twice, with and without template clustering: a cluster sends
// one request for all templates that ask for the same one and evaluates them
// on one shared response, with the variables of its first template only.
func TestNucleiTemplateFeatures(t *testing.T) {
	bin := nucleiBin(t)
	rules, icon := featureRules(t)
	// The expectations of the field rules are the scanner's: their tests
	// list every field they read, so they must pass in eval.
	for _, r := range fieldRules(t) {
		c, _, err := eval.Compile(r)
		if err != nil {
			t.Fatalf("%s: %v", r.Path, err)
		}
		for _, tr := range c.RunTests() {
			if !tr.Passed {
				t.Errorf("%s: %s: %s", r.Path, tr.Name, tr.Detail)
			}
		}
		rules = append(rules, r)
	}
	rules = append(rules, markerRule(t))
	extra := []nucleiCase{
		{rule: "athar-features-hashes", test: "hashes: same favicon and body", target: serveIconPage(t, icon), expect: true},
		{rule: "athar-features-hashes", test: "hashes: other favicon", target: serveIconPage(t, []byte("other")), expect: false},
		// An empty answer is no favicon: the scanner has no hash fields then.
		{rule: "athar-features-no-favicon", test: "no favicon: empty answer", target: serveIconPage(t, nil), expect: true},
		{rule: "athar-features-no-favicon", test: "no favicon: an icon", target: serveIconPage(t, icon), expect: false},
	}
	// target.tls: the same page over TLS and in plaintext.
	for i, mode := range []string{"required", "none"} {
		rules = append(rules, parse(t, "features_tls_"+mode+".yml", `
title: tls `+mode+`
id: 55555555-5555-4555-8555-55555555555`+fmt.Sprint(i)+`
target: {protocol: http, tls: `+mode+`}
detection:
  selection:
    http.title: 'Hash test'
  condition: selection
`))
		// The scheme guard around an OR and a guarded title.
		rules = append(rules, parse(t, "features_tls_"+mode+"_fields.yml", `
title: tls `+mode+` with fields
id: 55555555-5555-4555-8555-55555555556`+fmt.Sprint(i)+`
target: {protocol: http, tls: `+mode+`}
detection:
  selection_title:
    http.title|startswith: 'Hash'
  selection_header:
    http.headers.x-none|exists: true
  filter_empty:
    http.title: ''
  condition: (selection_title or selection_header) and not filter_empty
`))
	}
	plain, secure := serveIconPage(t, icon), servePageTLS(t)
	extra = append(extra,
		nucleiCase{rule: "athar-features-tls-required-fields", test: "tls required, fields: over TLS", target: secure, expect: true},
		nucleiCase{rule: "athar-features-tls-required-fields", test: "tls required, fields: plaintext", target: plain, expect: false},
		nucleiCase{rule: "athar-features-tls-none-fields", test: "tls none, fields: plaintext", target: plain, expect: true},
		nucleiCase{rule: "athar-features-tls-none-fields", test: "tls none, fields: over TLS", target: secure, expect: false},
		nucleiCase{rule: "athar-features-tls-required", test: "tls required: over TLS", target: secure, expect: true},
		nucleiCase{rule: "athar-features-tls-required", test: "tls required: plaintext", target: plain, expect: false},
		nucleiCase{rule: "athar-features-tls-none", test: "tls none: plaintext", target: plain, expect: true},
		nucleiCase{rule: "athar-features-tls-none", test: "tls none: over TLS", target: secure, expect: false},
	)
	for _, mode := range []struct {
		name  string
		flags []string
	}{{"clustered", nil}, {"unclustered", []string{"-dc"}}} {
		t.Run(mode.name, func(t *testing.T) {
			nucleiCheck(t, bin, rules, extra[:len(extra):len(extra)], true, mode.flags...)
		})
	}
}

// markerRule has what Nuclei would expand or mistake in a template: {{…}}
// in values and in an extract pattern, and probe ids that are no names.
func markerRule(t *testing.T) *rule.Rule {
	return parse(t, "features_markers.yml", `
title: markers
id: 55555555-5555-4555-8555-555555555555
probes:
  ssl:
    protocol: http
    request:
      path: /app.js
  api/v1:
    protocol: http
    request:
      path: /api/v1
detection:
  selection_body:
    http.body|contains: '{{ message }}'
  selection_cased:
    http.body|contains|cased: '{{Hostname}}'
  selection_re:
    http.body|re: 'id=\w+>{{ ?\w+ ?}}<'
  selection_encoded:
    http.body|contains: '%7B%7Bhost%7D%7D'
  selection_script:
    probe: ssl
    http.body|contains: 'on {{host}}'
  selection_api:
    probe: api/v1
    http.status_code: 204
  condition: all of selection_*
extract:
  app:
    field: http.body
    regex: '{{randstr}} (\w+)'
tests:
  - name: template text
    expect: match
    response:
      http.body: '<div id=app>{{ message }}</div> {{Hostname}} %7B%7Bhost%7D%7D {{randstr}} vue'
    probes:
      ssl:
        http.body: 'on {{host}}'
      api/v1:
        http.status_code: 204
    extracted:
      app: vue
  - name: rendered text
    expect: no_match
    response:
      http.body: '<div id=app>hello</div> {{Hostname}} %7B%7Bhost%7D%7D {{randstr}} vue'
    probes:
      ssl:
        http.body: 'on {{host}}'
      api/v1:
        http.status_code: 204
  - name: host name in place of the marker
    expect: no_match
    response:
      http.body: '<div id=app>{{ message }}</div> {{Hostname}} %7B%7Bhost%7D%7D {{randstr}} vue'
    probes:
      ssl:
        http.body: 'on 127.0.0.1'
      api/v1:
        http.status_code: 204
  - name: no API
    expect: no_match
    response:
      http.body: '<div id=app>{{ message }}</div> {{Hostname}} %7B%7Bhost%7D%7D {{randstr}} vue'
    probes:
      ssl:
        http.body: 'on {{host}}'
`)
}

// featurePage is what serveIconPage serves at /.
const featurePage = "<html><head><title>Hash test</title></head><body>hashed</body></html>"

// featureRules are rules that use what the repository's rules don't use yet.
// The last one checks hashes of featurePage and of the returned icon.
func featureRules(t *testing.T) ([]*rule.Rule, []byte) {
	t.Helper()
	icon := []byte("\x00\x00\x01\x00 not really an icon")
	page := featurePage
	sum := func(b []byte) string { s := sha256.Sum256(b); return hex.EncodeToString(s[:]) }
	md := md5.Sum(icon)
	hashes := fmt.Sprintf(`
title: hashes
id: 22222222-2222-4222-8222-222222222222
detection:
  selection_icon:
    http.favicon.mmh3: %d
  selection_icon_md5:
    http.favicon.md5: %s
  selection_icon_sha256:
    http.favicon.sha256: %s
  selection_body_sha256:
    http.body.sha256: %s
  selection_body_mmh3:
    http.body.mmh3: %d
  condition: all of selection_*
`, probe.FaviconMMH3(icon), hex.EncodeToString(md[:]), sum(icon), sum([]byte(page)), probe.MMH3([]byte(page)))

	rules := []*rule.Rule{
		parse(t, "features_http.yml", `
title: features
id: 11111111-1111-4111-8111-111111111111
detection:
  selection_title:
    http.title|startswith: 'acme'
  selection_wild:
    http.title: 'Acme * Console'
  selection_server:
    http.headers.server|contains: 'acme'
  selection_status:
    http.status_code: 200
  selection_cased:
    http.body|contains|cased: 'MixedCase'
  filter_proxy:
    http.headers.x-powered-by: 'nginx'
  condition: selection_title and selection_wild and selection_server and selection_status and selection_cased and not filter_proxy
extract:
  version:
    field: http.headers.server
    regex: '(?i)acme/([0-9.]+)'
tests:
  - name: all signals
    expect: match
    response:
      http.title: 'Acme Ops Console'
      http.headers.server: 'Acme/1.2'
      http.body: 'x MixedCase x'
    extracted:
      version: '1.2'
  - name: wrong case in the body
    expect: no_match
    response:
      http.title: 'Acme Ops Console'
      http.headers.server: 'Acme/1.2'
      http.body: 'x mixedcase x'
  - name: behind the filtered proxy
    expect: no_match
    response:
      http.title: 'Acme Ops Console'
      http.headers.server: 'Acme/1.2'
      http.headers.x-powered-by: 'nginx'
      http.body: 'x MixedCase x'
  - name: other status
    expect: no_match
    response:
      http.status_code: 404
      http.title: 'Acme Ops Console'
      http.headers.server: 'Acme/1.2'
      http.body: 'x MixedCase x'
  - name: title without the wildcard part
    expect: no_match
    response:
      http.title: 'Acme Ops'
      http.headers.server: 'Acme/1.2'
      http.body: 'x MixedCase x'
`),
		parse(t, "features_probe.yml", `
title: probe
id: 33333333-3333-4333-8333-333333333333
probes:
  health:
    protocol: http
    request:
      method: HEAD
      path: /api/health
detection:
  keywords:
    - 'powered-by-acme'
  selection_raw:
    http.headers_raw|contains: 'x-acme-trace'
  selection_health:
    probe: health
    http.status_code: 204
  condition: keywords and selection_raw and selection_health
tests:
  - name: keyword, header and health check
    expect: match
    response:
      http.headers.x-acme-trace: 'abc'
      http.body: 'powered-by-acme'
    probes:
      health:
        http.status_code: 204
  - name: no health check
    expect: no_match
    response:
      http.headers.x-acme-trace: 'abc'
      http.body: 'powered-by-acme'
  - name: no keyword
    expect: no_match
    response:
      http.headers.x-acme-trace: 'abc'
      http.body: 'nothing here'
    probes:
      health:
        http.status_code: 204
`),
		parse(t, "features_tls.yml", `
title: tls
id: 44444444-4444-4444-8444-444444444444
detection:
  selection_cn:
    tls.cert.subject.cn: 'acme panel'
  selection_san:
    tls.cert.san|endswith: '.acme.example'
  selection_san_name:
    tls.cert.san: 'other.example'
  filter_ca:
    tls.cert.issuer.o: 'Evil CA'
  condition: selection_cn and selection_san and selection_san_name and not filter_ca
tests:
  - name: panel certificate
    expect: match
    response:
      tls.cert.subject.cn: 'Acme Panel'
      tls.cert.san: ['other.example', 'panel.acme.example']
      tls.cert.issuer.o: 'Good CA'
  - name: SAN suffix only inside a name
    expect: no_match
    response:
      tls.cert.subject.cn: 'Acme Panel'
      tls.cert.san: ['other.example', 'panel.acme.example.org']
  - name: filtered issuer
    expect: no_match
    response:
      tls.cert.subject.cn: 'Acme Panel'
      tls.cert.san: ['other.example', 'panel.acme.example']
      tls.cert.issuer.o: 'Evil CA'
`),
		parse(t, "features_hashes.yml", hashes),
	}
	return rules, icon
}

// fieldRules check that a template reads a field as the scanner does: an
// absent field fails every comparison, a repeated header matches if one of
// its values does, and letters fold as in Go's (?i).
func fieldRules(t *testing.T) []*rule.Rule {
	t.Helper()
	return []*rule.Rule{
		// Three templates that ask for the same request, so Nuclei clusters
		// them. The response has no title and no X-Absent header.
		parse(t, "features_not_title.yml", `
title: not title
id: 55555555-5555-4555-8555-555555555501
detection:
  selection:
    http.status_code: 302
  filter:
    http.title|contains: 'zzz'
  condition: selection and not filter
tests:
  - name: redirect without a title
    expect: match
    response:
      http.status_code: 302
      http.headers.location: '/login'
  - name: redirect with the filtered title
    expect: no_match
    response:
      http.status_code: 302
      http.title: 'a zzz page'
`),
		parse(t, "features_not_header.yml", `
title: not header
id: 55555555-5555-4555-8555-555555555502
detection:
  selection:
    http.status_code: 302
  filter:
    http.headers.x-absent|contains: 'zzz'
  condition: selection and not filter
tests:
  - name: redirect without the header
    expect: match
    response:
      http.status_code: 302
      http.headers.location: '/login'
  - name: redirect with the filtered header
    expect: no_match
    response:
      http.status_code: 302
      http.headers.x-absent: 'a zzz value'
`),
		parse(t, "features_title_or_header.yml", `
title: title or header
id: 55555555-5555-4555-8555-555555555503
detection:
  selection_title:
    http.title|contains: 'nothing'
  selection_location:
    http.headers.location|contains: '/login'
  condition: selection_title or selection_location
tests:
  - name: redirect without a title
    expect: match
    response:
      http.status_code: 302
      http.headers.location: '/login'
  - name: redirect elsewhere
    expect: no_match
    response:
      http.status_code: 302
      http.headers.location: '/home'
`),
		// A page without a title has no title; it does not have an empty one.
		parse(t, "features_empty_title.yml", `
title: empty title
id: 55555555-5555-4555-8555-555555555504
detection:
  selection_status:
    http.status_code: 302
  selection_empty:
    http.title|re: '^$'
  condition: selection_status and selection_empty
tests:
  - name: empty title
    expect: match
    response:
      http.status_code: 302
      http.title: ''
  - name: no title
    expect: no_match
    response:
      http.status_code: 302
`),
		parse(t, "features_not_empty_title.yml", `
title: not empty title
id: 55555555-5555-4555-8555-555555555505
detection:
  selection_status:
    http.status_code: 302
  filter_empty:
    http.title: ''
  condition: selection_status and not filter_empty
tests:
  - name: no title
    expect: match
    response:
      http.status_code: 302
  - name: empty title
    expect: no_match
    response:
      http.status_code: 302
      http.title: ''
  - name: some title
    expect: match
    response:
      http.status_code: 302
      http.title: 'Moved'
`),
		parse(t, "features_exists.yml", `
title: exists
id: 55555555-5555-4555-8555-555555555506
detection:
  selection:
    http.title|exists: false
    http.headers.x-here|exists: true
    http.headers.x-gone: null
  condition: selection
tests:
  - name: header with an empty value, no title
    expect: match
    response:
      http.headers.x-here: ''
      http.body: 'plain'
  - name: with a title
    expect: no_match
    response:
      http.headers.x-here: ''
      http.title: 'Here'
  - name: without the header
    expect: no_match
    response:
      http.body: 'plain'
  - name: with the header that must be absent
    expect: no_match
    response:
      http.headers.x-here: 'yes'
      http.headers.x-gone: 'no'
      http.body: 'plain'
`),
		// Every value of a repeated header is compared on its own.
		parse(t, "features_repeated_header.yml", `
title: repeated header
id: 55555555-5555-4555-8555-555555555507
detection:
  selection_start:
    http.headers.set-cookie|startswith: 'session='
  selection_equal:
    http.headers.x-multi: 'two'
  selection_end:
    http.headers.x-multi|endswith: 'ne'
  selection_cased:
    http.headers.x-multi|contains|cased: 'Tw'
  selection_regex:
    http.headers.x-multi|re: '^T.o$'
  selection_wildcard:
    http.headers.x-multi: 't?o'
  filter_joined:
    http.headers.x-multi|contains: 'one two'
  condition: all of selection_* and not filter_joined
tests:
  - name: two cookies, two values
    expect: match
    response:
      http.headers.set-cookie: ['a=1; Path=/', 'session=xyz; HttpOnly']
      http.headers.x-multi: ['one', 'Two']
  - name: both words in one value
    expect: no_match
    response:
      http.headers.set-cookie: ['a=1; Path=/', 'session=xyz; HttpOnly']
      http.headers.x-multi: 'one Two'
  - name: cookie name inside a value
    expect: no_match
    response:
      http.headers.set-cookie: 'a=1; session=xyz'
      http.headers.x-multi: ['one', 'Two']
`),
		// Go's (?i) folds a final sigma and a long s, and does not fold a
		// dotted capital I to i; tolower() does the opposite.
		parse(t, "features_folding.yml", `
title: folding
id: 55555555-5555-4555-8555-555555555508
detection:
  selection_sigma:
    http.body|contains: 'ΟΔΟΣ ΟΔΟΣ'
  selection_long_s:
    http.title: 'Glass'
  condition: selection_sigma and selection_long_s
tests:
  - name: final sigma and long s
    expect: match
    response:
      http.title: 'GLAſS'
      http.body: 'ΟΔΟΣ οδος'
  - name: other word
    expect: no_match
    response:
      http.title: 'GLAſS'
      http.body: 'ΟΔΟΣ οδοι'
`),
		parse(t, "features_folding_ascii.yml", `
title: folding of an ASCII value
id: 55555555-5555-4555-8555-555555555509
detection:
  selection:
    http.body|contains: 'panel'
  filter:
    http.body|contains: 'istanbul'
  condition: selection and not filter
tests:
  - name: dotted capital I
    expect: match
    response:
      http.body: 'İstanbul panel'
  - name: plain capital I
    expect: no_match
    response:
      http.body: 'Istanbul panel'
`),
		// A certificate without an organisation, and no certificate at all.
		parse(t, "features_tls_absent.yml", `
title: absent certificate fields
id: 55555555-5555-4555-8555-555555555510
detection:
  selection_cn:
    tls.cert.subject.cn: 'acme panel'
  selection_no_org:
    tls.cert.subject.o|exists: false
  filter_issuer:
    tls.cert.issuer.o: 'Evil CA'
  condition: selection_cn and selection_no_org and not filter_issuer
tests:
  - name: self-signed without an organisation
    expect: match
    response:
      tls.cert.subject.cn: 'Acme Panel'
  - name: with an organisation
    expect: no_match
    response:
      tls.cert.subject.cn: 'Acme Panel'
      tls.cert.subject.o: 'Acme'
`),
		parse(t, "features_no_tls.yml", `
title: no certificate
id: 55555555-5555-4555-8555-555555555511
detection:
  selection:
    http.title: 'Plain'
  filter:
    tls.cert.subject.cn|re: '^$'
  condition: selection and not filter
tests:
  - name: plain HTTP
    expect: match
    response:
      http.title: 'Plain'
  - name: other title
    expect: no_match
    response:
      http.title: 'Other'
`),
		// Served by serveIconPage.
		parse(t, "features_no_favicon.yml", `
title: no favicon
id: 55555555-5555-4555-8555-555555555512
detection:
  selection_title:
    http.title: 'Hash test'
  selection_none:
    http.favicon.md5|exists: false
  filter_empty:
    http.favicon.mmh3: 0
  condition: selection_title and selection_none and not filter_empty
`),
		// {{…}} in the expressions that read a header line and the title.
		parse(t, "features_markers_fields.yml", `
title: markers in fields
id: 55555555-5555-4555-8555-555555555513
detection:
  selection_header:
    http.headers.x-app: '{{host}}'
  selection_header_re:
    http.headers.x-app|re: '^{{h\w+}}$'
  selection_encoded:
    http.headers.x-enc|contains: '%7B%7Bhost'
  selection_title:
    http.title|startswith|cased: '{{Hostname}}'
  selection_fold:
    http.title|contains: '{{hostname}} is'
  condition: all of selection_*
tests:
  - name: marker text
    expect: match
    response:
      http.headers.x-app: '{{host}}'
      http.headers.x-enc: 'a=%7B%7Bhost%7D%7D'
      http.title: '{{Hostname}} is up'
  - name: expanded header
    expect: no_match
    response:
      http.headers.x-app: '127.0.0.1'
      http.headers.x-enc: 'a=%7B%7Bhost%7D%7D'
      http.title: '{{Hostname}} is up'
  - name: expanded title
    expect: no_match
    response:
      http.headers.x-app: '{{host}}'
      http.headers.x-enc: 'a=%7B%7Bhost%7D%7D'
      http.title: '127.0.0.1 is up'
`),
	}
}

// serveIconPage serves featurePage at / and ico at /favicon.ico.
func serveIconPage(t *testing.T, ico []byte) string {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/favicon.ico" {
			w.Write(ico)
			return
		}
		fmt.Fprint(w, featurePage)
	}))
	t.Cleanup(srv.Close)
	return srv.URL
}

// servePageTLS serves featurePage at / over TLS.
func servePageTLS(t *testing.T) string {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, featurePage)
	}))
	t.Cleanup(srv.Close)
	return srv.URL
}

func nucleiBin(t *testing.T) string {
	t.Helper()
	bin, err := exec.LookPath("nuclei")
	if err != nil {
		t.Skip("nuclei not installed")
	}
	if testing.Short() {
		t.Skip("runs nuclei")
	}
	return bin
}

func parse(t *testing.T, path, src string) *rule.Rule {
	t.Helper()
	r, err := rule.Parse([]byte(src), path)
	if err != nil {
		t.Fatal(err)
	}
	return r
}

type nucleiCase struct {
	rule, test, target string
	expect             bool
	extracted          map[string]string
	fid                Fidelity
}

// nucleiCheck converts the rules, serves their tests, runs Nuclei once over
// all templates and targets, and compares. strict also holds approximate
// templates to the expected result. flags are added to Nuclei's.
func nucleiCheck(t *testing.T, bin string, rules []*rule.Rule, cases []nucleiCase, strict bool, flags ...string) {
	t.Helper()
	dir := t.TempDir()
	fids := map[string]Fidelity{}
	skipped := 0
	for _, r := range rules {
		if _, _, err := eval.Compile(r); err != nil {
			t.Fatalf("%s: %v", r.Path, err)
		}
		res, err := Convert(r, nucleiTarget)
		if err != nil {
			t.Fatalf("%s: %v", r.Path, err)
		}
		if res.Template == "" {
			continue
		}
		fids[res.TemplateID] = res.Fidelity
		if err := os.WriteFile(filepath.Join(dir, res.TemplateID+".yaml"), []byte(res.Template), 0o644); err != nil {
			t.Fatal(err)
		}
		for _, tc := range r.Tests {
			srv, ok := serveTest(t, r, tc)
			if !ok {
				skipped++
				continue
			}
			cases = append(cases, nucleiCase{res.TemplateID, filepath.Base(r.Path) + ": " + tc.Name, srv, tc.Expect == "match", tc.Extracted, 0})
		}
	}
	var targets []string
	for i := range cases {
		cases[i].fid = fids[cases[i].rule]
		targets = append(targets, cases[i].target)
	}
	list := filepath.Join(dir, "targets.txt")
	if err := os.WriteFile(list, []byte(strings.Join(targets, "\n")+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(bin, append([]string{"-duc", "-silent", "-nc", "-jsonl", "-t", dir, "-l", list, "-timeout", "5", "-retries", "0"}, flags...)...)
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("nuclei: %v\n%s", err, out)
	}
	hit := map[string]bool{}
	extracted := map[string][]string{}
	sc := bufio.NewScanner(strings.NewReader(string(out)))
	sc.Buffer(nil, 1<<20)
	for sc.Scan() {
		var ev struct {
			TemplateID string   `json:"template-id"`
			Host       string   `json:"host"`
			URL        string   `json:"url"`
			MatchedAt  string   `json:"matched-at"`
			Extracted  []string `json:"extracted-results"`
		}
		if json.Unmarshal(sc.Bytes(), &ev) != nil {
			continue
		}
		for _, s := range []string{ev.Host, ev.URL, ev.MatchedAt} {
			if u, err := url.Parse(s); err == nil && u.Host != "" {
				s = u.Host
			}
			if s != "" {
				hit[ev.TemplateID+" "+s] = true
				extracted[ev.TemplateID+" "+s] = append(extracted[ev.TemplateID+" "+s], ev.Extracted...)
			}
		}
	}
	matches := 0
	for _, c := range cases {
		u, _ := url.Parse(c.target)
		key := c.rule + " " + u.Host
		got := hit[key]
		if got {
			matches++
		}
		hard := strict || c.fid == Exact || (c.fid == Superset && c.expect)
		if got != c.expect {
			if hard {
				t.Errorf("%s (%s): nuclei matched=%v, test expects %v", c.test, c.fid, got, c.expect)
			} else {
				t.Logf("%s (%s): nuclei matched=%v, test expects %v", c.test, c.fid, got, c.expect)
			}
			continue
		}
		for name, want := range c.extracted {
			found := false
			for _, v := range extracted[key] {
				found = found || v == want
			}
			if !found && hard {
				t.Errorf("%s: extract %s: want %q, nuclei extracted %q", c.test, name, want, extracted[key])
			}
		}
	}
	if matches == 0 {
		t.Errorf("nuclei matched nothing; the harness is broken")
	}
	t.Logf("%d test responses checked with nuclei (%d matches), %d skipped", len(cases), matches, skipped)
}

// serveTest starts a server that answers like one rule test: the baseline
// response at / and custom probe responses at their paths. It returns the
// target URL, or false if the response can't be rebuilt from its fields.
func serveTest(t *testing.T, r *rule.Rule, tc rule.Test) (string, bool) {
	t.Helper()
	type page struct {
		status  int
		headers http.Header
		body    string
	}
	build := func(resp map[string]any) (page, bool) {
		p := page{status: 200, headers: http.Header{}}
		var title string
		hasTitle := false
		for k, v := range resp {
			switch {
			case k == "http.status_code":
				fmt.Sscan(fmt.Sprint(v), &p.status)
			case k == "http.title":
				title, hasTitle = fmt.Sprint(v), true
			case k == "http.body":
				p.body = fmt.Sprint(v)
			case k == "http.headers_raw":
				for _, line := range strings.Split(fmt.Sprint(v), "\n") {
					if name, val, ok := strings.Cut(strings.TrimRight(line, "\r"), ":"); ok && !strings.HasPrefix(name, "HTTP/") {
						p.headers.Add(strings.TrimSpace(name), strings.TrimSpace(val))
					}
				}
			case strings.HasPrefix(k, "http.headers."):
				name := strings.TrimPrefix(k, "http.headers.")
				if list, ok := v.([]any); ok {
					for _, e := range list {
						p.headers.Add(name, fmt.Sprint(e))
					}
				} else {
					p.headers.Set(name, fmt.Sprint(v))
				}
			case strings.HasPrefix(k, "tls.cert.subject."), strings.HasPrefix(k, "tls.cert.issuer."), k == "tls.cert.san",
				k == "service.protocol", k == "service.transport", k == "service.port":
			default:
				return p, false // hashes, banners, other TLS fields: can't be rebuilt
			}
		}
		if hasTitle {
			p.body = "<html><head><title>" + html.EscapeString(title) + "</title></head><body>\n" + p.body + "</body></html>"
		}
		return p, true
	}
	pages := map[string]page{}
	if tc.Response != nil {
		p, ok := build(tc.Response)
		if !ok {
			return "", false
		}
		pages["/"] = p
	}
	for id, resp := range tc.Probes {
		pr, ok := r.Probes[id]
		if !ok || pr.Request == nil {
			return "", false
		}
		p, ok := build(resp)
		if !ok {
			return "", false
		}
		path := pr.Request.Path
		if path == "" {
			path = "/"
		}
		pages[path] = p
	}
	h := http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		p, ok := pages[req.URL.RequestURI()]
		if !ok {
			w.WriteHeader(404)
			return
		}
		for k, vs := range p.headers {
			w.Header()[http.CanonicalHeaderKey(k)] = vs
		}
		w.WriteHeader(p.status)
		fmt.Fprint(w, p.body)
	})
	srv := httptest.NewUnstartedServer(h)
	if cert, ok := testCert(t, tc.Response); ok {
		srv.TLS = &tls.Config{Certificates: []tls.Certificate{cert}}
		srv.StartTLS()
	} else {
		srv.Start()
	}
	t.Cleanup(srv.Close)
	return srv.URL, true
}

// testCert builds a certificate with the test's subject, issuer and SAN
// fields, or returns false if the test has none.
func testCert(t *testing.T, resp map[string]any) (tls.Certificate, bool) {
	strs := func(k string) []string {
		switch v := resp[k].(type) {
		case nil:
			return nil
		case []any:
			var out []string
			for _, e := range v {
				out = append(out, fmt.Sprint(e))
			}
			return out
		default:
			return []string{fmt.Sprint(v)}
		}
	}
	hasTLS := false
	for k := range resp {
		hasTLS = hasTLS || strings.HasPrefix(k, "tls.")
	}
	if !hasTLS {
		return tls.Certificate{}, false
	}
	subject := pkix.Name{Organization: strs("tls.cert.subject.o")}
	if cn := strs("tls.cert.subject.cn"); cn != nil {
		subject.CommonName = cn[0]
	}
	issuer := pkix.Name{Organization: strs("tls.cert.issuer.o")}
	if cn := strs("tls.cert.issuer.cn"); cn != nil {
		issuer.CommonName = cn[0]
	}
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	leaf := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      subject,
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	for _, s := range strs("tls.cert.san") {
		if ip := net.ParseIP(s); ip != nil {
			leaf.IPAddresses = append(leaf.IPAddresses, ip)
		} else {
			leaf.DNSNames = append(leaf.DNSNames, s)
		}
	}
	parent := leaf
	if issuer.CommonName != "" || len(issuer.Organization) > 0 {
		parent = &x509.Certificate{
			SerialNumber:          big.NewInt(1),
			Subject:               issuer,
			NotBefore:             leaf.NotBefore,
			NotAfter:              leaf.NotAfter,
			IsCA:                  true,
			BasicConstraintsValid: true,
			KeyUsage:              x509.KeyUsageCertSign,
		}
	}
	der, err := x509.CreateCertificate(rand.Reader, leaf, parent, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}, true
}
