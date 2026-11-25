package convert

import (
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
	})
	check(t, ruleFrom(t, specVariant), map[string]want{
		"fofa":    {`title="Autonomous Penetration Testing Console" && body="/function/tasks" && (title="ARTEX" || icon_hash="-576220750")`, Approximate},
		"shodan":  {`http.title:"Autonomous Penetration Testing Console" http.html:"/function/tasks"`, Superset},
		"censys":  {`host.services: (endpoints.http.html_title: "Autonomous Penetration Testing Console" and endpoints.http.body: "/function/tasks")`, Superset},
		"zoomeye": {`title="Autonomous Penetration Testing Console" && http.body="/function/tasks" && (title="ARTEX" || iconhash="-576220750")`, Approximate},
		"modat":   {`http.title~"Autonomous Penetration Testing Console" and http.body~"/function/tasks" and (http.title=~"^ARTEX" or http.files.mmh3=-576220750)`, Approximate},
	})
	check(t, ruleFrom(t, specBasicAuth), map[string]want{
		"modat":   {`http.headers: (key = "Www-Authenticate" and value = "Basic realm=\"ARTEX\", charset=\"UTF-8\"")`, Exact},
		"fofa":    {`header="Basic realm=\"ARTEX\", charset=\"UTF-8\""`, Approximate},
		"zoomeye": {`http.header="Basic realm=\"ARTEX\", charset=\"UTF-8\""`, Approximate},
		"censys":  {"", Unsupported},
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
		"fofa": {`title="Console" && (body!="x" || header!="y")`, Approximate},
	})
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
		"shodan": {`http.title:"自主渗透测试控制台","자율 침투 테스트 콘솔","Autonomous Penetration Testing Console"`, Approximate},
		"fofa":   {`title="自主渗透测试控制台" || title="자율 침투 테스트 콘솔" || title="Autonomous Penetration Testing Console"`, Exact},
	})
	// Different filters still can't be ORed on Shodan.
	r := ruleFrom(t, "a:\n  http.title|contains: x\nb:\n  http.favicon.mmh3: 1\nport:\n  service.port: 443\ncondition: (a or b) and port\n")
	check(t, r, map[string]want{"shodan": {"port:443", Superset}})
	// A negated value is not listed.
	r = ruleFrom(t, "a:\n  http.title|contains: x\nb:\n  http.title|contains: y\nport:\n  service.port: 443\ncondition: port and (a or not b)\n")
	check(t, r, map[string]want{"shodan": {"port:443", Superset}})
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
