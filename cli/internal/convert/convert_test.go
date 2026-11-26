package convert

import (
	"os"
	"strings"
	"testing"

	"github.com/Athar-HQ/Athar/cli/internal/eval"
	"github.com/Athar-HQ/Athar/cli/internal/rule"
)

func ruleFrom(t *testing.T, detection string) *rule.Rule {
	t.Helper()
	src := "title: t\ndetection:\n"
	for _, line := range strings.Split(strings.TrimRight(detection, "\n"), "\n") {
		src += "  " + line + "\n"
	}
	src += "probes:\n  api: { protocol: http, request: { path: /api } }\n"
	r, err := rule.Parse([]byte(src), "t.yml")
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := eval.Compile(r); err != nil {
		t.Fatalf("rule does not compile: %v", err)
	}
	return r
}

// Fixed copies of the rules in spec section 10, so edits to the live rules
// don't change what these tests check.
const (
	specFamily = `
selection_title:
  http.title|contains: 'Autonomous Penetration Testing Console'
selection_route:
  http.body|contains: '/function/tasks'
condition: selection_title and selection_route
`
	specVariant = `
selection_title:
  http.title|contains: 'Autonomous Penetration Testing Console'
selection_route:
  http.body|contains: '/function/tasks'
selection_brand:
  http.title|startswith: 'ARTEX'
selection_icon:
  http.favicon.mmh3: -576220750
condition: selection_title and selection_route and (selection_brand or selection_icon)
`
	specBasicAuth = `
selection_realm:
  http.headers.www-authenticate: 'Basic realm="ARTEX", charset="UTF-8"'
condition: selection_realm
`
	localizedFamily = `
selection_title:
  http.title|contains:
    - '自主渗透测试控制台'
    - '자율 침투 테스트 콘솔'
    - 'Autonomous Penetration Testing Console'
condition: selection_title
`
)

type want struct {
	query string
	fid   Fidelity
}

func check(t *testing.T, r *rule.Rule, cases map[string]want) {
	t.Helper()
	for engine, w := range cases {
		res, err := Convert(r, engine)
		if err != nil {
			t.Fatalf("%s: %v", engine, err)
		}
		if res.Query != w.query || res.Fidelity != w.fid {
			t.Errorf("%s:\n got  [%s] %s\nwant [%s] %s\nnotes: %v", engine, res.Fidelity, res.Query, w.fid, w.query, res.Notes)
		}
	}
}

// The family and variant conversions in spec section 10.
func TestSpecExamples(t *testing.T) {
	check(t, ruleFrom(t, specFamily), map[string]want{
		"fofa":    {`title="Autonomous Penetration Testing Console" && body="/function/tasks"`, Exact},
		"shodan":  {`http.title:"Autonomous Penetration Testing Console" http.html:"/function/tasks"`, Approximate},
		"censys":  {`host.services: (endpoints.http.html_title: "Autonomous Penetration Testing Console" and endpoints.http.body: "/function/tasks")`, Approximate},
		"zoomeye": {`title="Autonomous Penetration Testing Console" && http.body="/function/tasks"`, Exact},
		"modat":   {`http.title~"Autonomous Penetration Testing Console" and http.body~"/function/tasks"`, Approximate},
		"urlscan": {`page.title.keyword:/.*autonomous penetration testing console.*/`, Superset},
	})
	check(t, ruleFrom(t, specVariant), map[string]want{
		"fofa":    {`title="Autonomous Penetration Testing Console" && body="/function/tasks" && (title="ARTEX" || icon_hash="-576220750")`, Approximate},
		"shodan":  {`http.title:"Autonomous Penetration Testing Console" http.html:"/function/tasks"`, Superset},
		"censys":  {`host.services: (endpoints.http.html_title: "Autonomous Penetration Testing Console" and endpoints.http.body: "/function/tasks")`, Superset},
		"zoomeye": {`title="Autonomous Penetration Testing Console" && http.body="/function/tasks" && (title="ARTEX" || iconhash="-576220750")`, Approximate},
		"modat":   {`http.title~"Autonomous Penetration Testing Console" and http.body~"/function/tasks" and (http.title=~"^ARTEX" or http.files.mmh3=-576220750)`, Approximate},
		"urlscan": {`page.title.keyword:/.*autonomous penetration testing console.*/`, Superset},
	})
	check(t, ruleFrom(t, specBasicAuth), map[string]want{
		"modat":   {`http.headers: (key = "Www-Authenticate" and value = "Basic realm=\"ARTEX\", charset=\"UTF-8\"")`, Exact},
		"fofa":    {`header="Basic realm=\"ARTEX\", charset=\"UTF-8\""`, Approximate},
		"zoomeye": {`http.header="Basic realm=\"ARTEX\", charset=\"UTF-8\""`, Approximate},
		"censys":  {"", Unsupported},
		"urlscan": {"", Unsupported},
	})
}

// Negations are pushed down to single conditions; a filter that can't be
// expressed is dropped, which widens the query (the superset rule).
func TestNegationAndSuperset(t *testing.T) {
	r := ruleFrom(t, `
sel:
  http.title|contains: Console
filter:
  http.favicon.mmh3: 123
condition: sel and not filter
`)
	check(t, r, map[string]want{
		"fofa":    {`title="Console" && icon_hash!="123"`, Exact},
		"shodan":  {`http.title:"Console" -http.favicon.hash:123`, Approximate},
		"modat":   {`http.title~"Console" and not http.files.mmh3=123`, Exact},
		"censys":  {`host.services: (endpoints.http.html_title: "Console")`, Superset},
		"zoomeye": {`title="Console" && iconhash!="123"`, Exact},
		"urlscan": {`page.title.keyword:/.*console.*/`, Superset},
	})

	// not (a or b) becomes not a and not b.
	r = ruleFrom(t, `
sel:
  http.title|contains: Console
a:
  http.body|contains: x
b:
  http.body|contains: y
condition: sel and not (a or b)
`)
	check(t, r, map[string]want{
		"fofa":  {`title="Console" && body!="x" && body!="y"`, Exact},
		"modat": {`http.title~"Console" and not http.body~"x" and not http.body~"y"`, Approximate},
	})

	// not (a and b) becomes not a or not b.
	r = ruleFrom(t, `
sel:
  http.title|contains: Console
pair:
  http.body|contains: x
  http.headers_raw|contains: y
condition: sel and not pair
`)
	check(t, r, map[string]want{
		"fofa": {`title="Console" && (body!="x" || header!="y")`, Exact},
	})

	// header= on FOFA and ZoomEye searches the raw block, so headers_raw
	// converts exactly; one named header is only approximate.
	r = ruleFrom(t, `
sel:
  http.title|contains: Console
proxy:
  http.headers_raw|contains: nginx
condition: sel and not proxy
`)
	check(t, r, map[string]want{
		"fofa":    {`title="Console" && header!="nginx"`, Exact},
		"zoomeye": {`title="Console" && http.header!="nginx"`, Exact},
	})
	r = ruleFrom(t, "sel:\n  http.headers.x-powered-by|contains: Express\ncondition: sel\n")
	if res, _ := Convert(r, "fofa"); res.Fidelity != Approximate || !strings.Contains(strings.Join(res.Notes, " "), "not one header") {
		t.Errorf("got %+v", res)
	}
}

func TestDroppedParts(t *testing.T) {
	// A custom-probe selection is never in an engine's index.
	r := ruleFrom(t, `
sel:
  http.title|contains: Console
api:
  probe: api
  http.body|contains: '"version"'
condition: sel and api
`)
	res, _ := Convert(r, "fofa")
	if res.Query != `title="Console"` || res.Fidelity != Superset || !strings.Contains(strings.Join(res.Notes, " "), "custom probe") {
		t.Errorf("got %+v", res)
	}

	// A rule that is only a regex is unsupported where there is no regex.
	r = ruleFrom(t, "sel:\n  http.title|re: '^AR(TEX|GOS)'\ncondition: sel\n")
	for _, engine := range []string{"fofa", "shodan", "zoomeye"} {
		if res, _ := Convert(r, engine); res.Fidelity != Unsupported || res.Query != "" {
			t.Errorf("%s: got %+v", engine, res)
		}
	}
	if res, _ := Convert(r, "modat"); res.Query != `http.title=~"^AR(TEX|GOS)"` || res.Fidelity != Approximate {
		t.Errorf("modat: got %+v", res)
	}

	// An OR on Shodan is dropped, leaving the rest.
	r = ruleFrom(t, "a:\n  http.title|contains: x\nb:\n  http.body|contains: y\nc:\n  service.port: 443\ncondition: (a or b) and c\n")
	if res, _ := Convert(r, "shodan"); res.Query != "port:443" || res.Fidelity != Superset {
		t.Errorf("shodan: got %+v", res)
	}
}

func TestOperatorsAndEscaping(t *testing.T) {
	r := ruleFrom(t, `
sel:
  http.title: 'Say "hi"'
  tls.cert.subject.cn|endswith: .example.org
condition: sel
`)
	check(t, r, map[string]want{
		"fofa":   {`title=="Say \"hi\"" && cert.subject.cn=".example.org"`, Approximate},
		"modat":  {`http.title="Say \"hi\"" and tls.subject.common_name=~"\.example\.org$"`, Exact},
		"censys": {`host.services: (endpoints.http.html_title = "Say \"hi\"" and cert.parsed.subject.common_name =~ "\.example\.org$")`, Approximate},
	})

	// Values lists: OR by default, AND with |all.
	r = ruleFrom(t, "sel:\n  http.title|contains|all: [a, b]\nalt:\n  http.title|contains: [c, d]\ncondition: sel or alt\n")
	check(t, r, map[string]want{
		"fofa": {`(title="a" && title="b") || title="c" || title="d"`, Exact},
	})

	// Sigma wildcards: Modat has them, the others drop the condition.
	r = ruleFrom(t, "sel:\n  http.title: 'AR*X Console'\nport:\n  service.port: 443\ncondition: sel and port\n")
	check(t, r, map[string]want{
		"modat": {`http.title="AR*X Console" and port=443`, Exact},
		"fofa":  {`port="443"`, Superset},
	})

	// Engine-specific fields only reach their own engine.
	r = ruleFrom(t, "sel:\n  x-fofa.app: ARTEX\nport:\n  service.port: 8443\ncondition: sel and port\n")
	check(t, r, map[string]want{
		"fofa":    {`app=="ARTEX" && port="8443"`, Exact},
		"zoomeye": {`port="8443"`, Superset},
	})
}

func TestUnknownEngine(t *testing.T) {
	if _, err := Convert(ruleFrom(t, specFamily), "bing"); err == nil {
		t.Error("want error for unknown engine")
	}
}

// Shodan has no OR, but lists several values of one filter with commas:
// http.title:"a","b" finds a or b (checked on shodan.io, 2026-11-25).
func TestShodanValueLists(t *testing.T) {
	check(t, ruleFrom(t, localizedFamily), map[string]want{
		"shodan":  {`http.title:"自主渗透测试控制台","자율 침투 테스트 콘솔","Autonomous Penetration Testing Console"`, Approximate},
		"fofa":    {`title="自主渗透测试控制台" || title="자율 침투 테스트 콘솔" || title="Autonomous Penetration Testing Console"`, Exact},
		"urlscan": {`page.title.keyword:/.*自主渗透测试控制台.*/ OR page.title.keyword:/.*자율 침투 테스트 콘솔.*/ OR page.title.keyword:/.*autonomous penetration testing console.*/`, Exact},
	})
	// Different filters still can't be ORed on Shodan.
	r := ruleFrom(t, "a:\n  http.title|contains: x\nb:\n  http.favicon.mmh3: 1\nport:\n  service.port: 443\ncondition: (a or b) and port\n")
	check(t, r, map[string]want{"shodan": {"port:443", Superset}})
	// A negated value is not listed.
	r = ruleFrom(t, "a:\n  http.title|contains: x\nb:\n  http.title|contains: y\nport:\n  service.port: 443\ncondition: port and (a or not b)\n")
	check(t, r, map[string]want{"shodan": {"port:443", Superset}})
}

// urlscan searches lowercase values, anchors its regexes, and reads
// a OR NOT b as a AND NOT b, so a negation inside OR gets its own group.
func TestUrlscan(t *testing.T) {
	r := ruleFrom(t, `
sel:
  http.status_code: 200
brand:
  http.title|startswith: 'ARTEX'
login:
  http.title: 'Login / Admin'
condition: sel and (brand or not login)
`)
	check(t, r, map[string]want{
		"urlscan": {`page.status:200 AND (page.title.keyword:/artex.*/ OR (NOT page.title.keyword:"login / admin"))`, Exact},
	})

	cases := []struct {
		detection string
		want      want
	}{
		// Sigma wildcards become regex wildcards; escaped ones stay literal.
		{`http.title: 'AR*X C?nsole \*'`, want{`page.title.keyword:/ar.*x c.nsole \*/`, Exact}},
		{`http.title|endswith: '.io'`, want{`page.title.keyword:/.*\.io/`, Exact}},
		// Everything is indexed in lowercase, so cased only approximates.
		{`http.title|contains|cased: ARTEX`, want{`page.title.keyword:/.*artex.*/`, Approximate}},
		// hash covers every response of the page load.
		{`http.favicon.sha256: ABCDEF01`, want{`hash:abcdef01`, Approximate}},
		{`http.headers.server|contains: 'nginx'`, want{`page.server:"nginx"`, Approximate}},
		{`tls.cert.issuer.cn|startswith: 'GTS CA'`, want{`page.tlsIssuer:gts\ ca*`, Exact}},
		{`tls.cert.issuer.cn|contains: 'GTS'`, want{"", Unsupported}},
		{`http.title|re: '^AR(TEX|GOS)'`, want{"", Unsupported}},
		{`http.body|contains: '/function/tasks'`, want{"", Unsupported}},
		{`http.headers.www-authenticate|contains: 'ARTEX'`, want{"", Unsupported}},
		{`service.port: 8787`, want{"", Unsupported}},
	}
	for _, c := range cases {
		check(t, ruleFrom(t, "sel:\n  "+c.detection+"\ncondition: sel\n"), map[string]want{"urlscan": c.want})
	}

	// A custom probe's body hash is the hash of the file it fetches, which
	// urlscan stores for every file a page loads. Other custom probe fields
	// are dropped, and other engines drop the whole selection.
	r = ruleFrom(t, `
css:
  probe: api
  http.body.sha256: FF75F55E
other:
  probe: api
  http.body.sha256: 0a1b2c3d
condition: css or other
`)
	check(t, r, map[string]want{
		"urlscan": {`hash:ff75f55e OR hash:0a1b2c3d`, Approximate},
		"fofa":    {"", Unsupported},
	})
	r = ruleFrom(t, "css:\n  probe: api\n  http.status_code: 200\n  http.body.sha256: ff75\ncondition: css\n")
	check(t, r, map[string]want{"urlscan": {`hash:ff75`, Superset}})
	r = ruleFrom(t, "title:\n  http.title|contains: Console\ncss:\n  probe: api\n  http.body.sha256: ff75\ncondition: title and not css\n")
	check(t, r, map[string]want{"urlscan": {`page.title.keyword:/.*console.*/`, Superset}})

	// Every query says what urlscan's records are.
	res, _ := Convert(ruleFrom(t, specFamily), "urlscan")
	if !strings.Contains(strings.Join(res.Notes, " "), "after redirects") {
		t.Errorf("missing the page-load note: %v", res.Notes)
	}
}

// Every rule in the repository converts for every engine without error.
func TestRepositoryRules(t *testing.T) {
	files, err := rule.Files([]string{"../../../rules"})
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range files {
		r, err := rule.Load(f)
		if err != nil {
			t.Fatal(err)
		}
		for _, engine := range Engines {
			res, err := Convert(r, engine)
			if err != nil {
				t.Errorf("%s %s: %v", f, engine, err)
			}
			if (res.Query == "") != (res.Fidelity == Unsupported) {
				t.Errorf("%s %s: query %q with fidelity %s", f, engine, res.Query, res.Fidelity)
			}
		}
	}
}

// Under not, a looser engine operator excludes more than the rule does, so
// the query would miss services the rule matches. A negated exact, prefix or
// suffix match that an engine can only search as a substring or as words is
// dropped instead, and the query stays a superset (spec section 10).
func TestNegatedLooserOperators(t *testing.T) {
	r := ruleFrom(t, `
sel:
  http.title|contains: Console
filter_prefix:
  http.title|startswith: ARTEX
filter_exact:
  http.title: Admin Console
filter_header:
  http.headers.x-powered-by|contains: Express
filter_server:
  http.headers.server|contains: nginx
condition: sel and not 1 of filter_*
`)
	check(t, r, map[string]want{
		"fofa":    {`title="Console" && server!="nginx"`, Superset},
		"zoomeye": {`title="Console" && http.header.server!="nginx"`, Superset},
		"shodan":  {`http.title:"Console"`, Superset},
		"modat":   {`http.title~"Console" and not http.title="Admin Console" and not http.headers: (key = "X-Powered-By" and value ~ "Express") and not http.title=~"^ARTEX" and not http.headers: (key = "Server" and value ~ "nginx")`, Exact},
	})
	for _, engine := range []string{"fofa", "zoomeye", "shodan"} {
		res, _ := Convert(r, engine)
		if notes := strings.Join(res.Notes, " "); !strings.Contains(notes, `not http.title|startswith "ARTEX"`) || !strings.Contains(notes, "would also exclude services the rule matches") {
			t.Errorf("%s: notes don't explain the dropped filter: %v", engine, res.Notes)
		}
	}

	// A negated exact match on one header: FOFA's server and urlscan's
	// page.server are searched as substring or words.
	r = ruleFrom(t, "sel:\n  http.title|contains: Console\nfilter:\n  http.headers.server: nginx\ncondition: sel and not filter\n")
	check(t, r, map[string]want{
		"fofa":    {`title="Console"`, Superset},
		"urlscan": {`page.title.keyword:/.*console.*/`, Superset},
	})

	// A negated substring search still converts.
	r = ruleFrom(t, "sel:\n  http.title|contains: Console\nfilter:\n  http.title|contains: ARTEX\ncondition: sel and not filter\n")
	check(t, r, map[string]want{
		"fofa":   {`title="Console" && title!="ARTEX"`, Exact},
		"shodan": {`http.title:"Console" -http.title:"ARTEX"`, Approximate},
	})
}

const unverifiedNote = "is not verified against the"

// Fields marked † in spec Appendix A are not checked against the engine's
// documentation. A query that uses one is approximate at best and says so.
func TestUnverifiedFields(t *testing.T) {
	cases := []struct {
		engine, detection, query string
	}{
		{"fofa", `http.headers.server|contains: nginx`, `server="nginx"`},
		{"fofa", `http.status_code: 200`, `status_code="200"`},
		{"fofa", `tls.cert.issuer.cn|contains: 'PentAGI CA'`, `cert.issuer.cn="PentAGI CA"`},
		{"shodan", `http.body.mmh3: 123`, `http.html_hash:123`},
		{"censys", `http.status_code: 200`, `host.services: (endpoints.http.status_code = "200")`},
		{"censys", `tls.cert.subject.cn|cased: Cairn`, `host.services: (cert.parsed.subject.common_name = "Cairn")`},
		{"censys", `tls.cert.issuer.cn|cased: 'PentAGI CA'`, `host.services: (cert.parsed.issuer.common_name = "PentAGI CA")`},
		{"modat", `http.body.mmh3: 123`, `http.body_mmh3=123`},
	}
	for _, c := range cases {
		r := ruleFrom(t, "sel:\n  "+c.detection+"\ncondition: sel\n")
		check(t, r, map[string]want{c.engine: {c.query, Approximate}})
		res, _ := Convert(r, c.engine)
		if !strings.Contains(strings.Join(res.Notes, " "), unverifiedNote+" "+c.engine+" docs") {
			t.Errorf("%s %s: no note that the field is unverified: %v", c.engine, c.detection, res.Notes)
		}
	}

	// Fields whose meaning on the engine is not recorded are not converted:
	// FOFA's body_hash (algorithm undocumented, docs/decisions.md), Shodan's
	// ssl.cert.fingerprint (hash not recorded), Censys headers and keywords.
	dropped := []struct{ engine, detection string }{
		{"fofa", "http.body.mmh3: 123"},
		{"shodan", "tls.cert.sha256: " + strings.Repeat("ab", 32)},
		{"censys", "http.headers.server|contains: nginx"},
		{"censys", "- ARTEX"},
	}
	for _, c := range dropped {
		r := ruleFrom(t, "sel:\n  "+c.detection+"\ncondition: sel\n")
		check(t, r, map[string]want{c.engine: {"", Unsupported}})
	}
}

// appendixRows gives a condition for every row of spec Appendix A.
var appendixRows = map[string]string{
	"`http.title`":          "http.title: x",
	"`http.body`":           "http.body: x",
	"`http.headers.server`": "http.headers.server: x",
	"other headers":         "http.headers.x-athar: x",
	"`http.status_code`":    "http.status_code: 200",
	"`http.favicon.mmh3`":   "http.favicon.mmh3: 123",
	"`http.favicon.md5`":    "http.favicon.md5: " + strings.Repeat("ab", 16),
	"`http.favicon.sha256`": "http.favicon.sha256: " + strings.Repeat("ab", 32),
	"`http.body.mmh3`":      "http.body.mmh3: 123",
	"`http.body.sha256`":    "http.body.sha256: " + strings.Repeat("ab", 32),
	"`tls.cert.subject.cn`": "tls.cert.subject.cn: x",
	"`tls.cert.issuer.cn`":  "tls.cert.issuer.cn: x",
	"`tls.cert.sha256`":     "tls.cert.sha256: " + strings.Repeat("ab", 32),
	"`tls.jarm`":            "tls.jarm: " + strings.Repeat("ab", 31),
	"`tls.ja3s`":            "tls.ja3s: " + strings.Repeat("ab", 16),
	"`service.banner`":      "service.banner: x",
	"`service.port`":        "service.port: 443",
	"`keywords`":            "- x",
}

// Spec Appendix A and the backends agree. A cell that starts with a dash or
// says "not converted" is a field no query uses; a cell marked † is a field
// the query uses with the unverified note and never as exact; every other
// cell is a field the query uses without that note.
func TestAppendixAMatchesBackends(t *testing.T) {
	spec, err := os.ReadFile("../../../spec/athar-spec.md")
	if err != nil {
		t.Fatal(err)
	}
	_, table, ok := strings.Cut(string(spec), "## Appendix A: Engine field mapping")
	if !ok {
		t.Fatal("spec has no Appendix A")
	}
	seen := map[string]bool{}   // rows found in the table
	marked := map[string]bool{} // engine and field of the † cells
	for _, line := range strings.Split(table, "\n") {
		cells := strings.Split(strings.Trim(line, "| "), " | ")
		detection, ok := appendixRows[cells[0]]
		if !ok {
			continue
		}
		if len(cells) != len(Engines)+1 {
			t.Fatalf("row %s has %d engine cells, want %d", cells[0], len(cells)-1, len(Engines))
		}
		seen[cells[0]] = true
		r := ruleFrom(t, "sel:\n  "+detection+"\ncondition: sel\n")
		for i, engine := range Engines {
			cell := cells[i+1]
			res, err := Convert(r, engine)
			if err != nil {
				t.Fatal(err)
			}
			noted := strings.Contains(strings.Join(res.Notes, " "), unverifiedNote)
			unverified := strings.Contains(cell, "†")
			switch {
			case strings.HasPrefix(cell, "—") || strings.Contains(cell, "not converted"):
				if res.Query != "" {
					t.Errorf("%s on %s: Appendix A says %q, but convert writes %s", cells[0], engine, cell, res.Query)
				}
				continue
			case res.Query == "":
				t.Errorf("%s on %s: Appendix A says %q, but convert writes no query: %v", cells[0], engine, cell, res.Notes)
			case unverified && (!noted || res.Fidelity == Exact):
				t.Errorf("%s on %s: Appendix A marks %q with †, but convert gives [%s] %s, notes %v", cells[0], engine, cell, res.Fidelity, res.Query, res.Notes)
			case !unverified && noted:
				t.Errorf("%s on %s: convert calls the field unverified, but Appendix A has no † on %q", cells[0], engine, cell)
			}
			if unverified {
				marked[engine+" "+strings.Trim(cells[0], "`")] = true
			}
		}
	}
	for row := range appendixRows {
		if !seen[row] {
			t.Errorf("Appendix A has no row %s", row)
		}
	}
	// Every field a backend marks as unverified has a † cell.
	for engine, fields := range fieldTables {
		for field, spec := range fields {
			if spec.unverified && !marked[engine+" "+field] {
				t.Errorf("%s: %s is unverified in backends.go but has no † cell in Appendix A", engine, field)
			}
		}
	}
}
