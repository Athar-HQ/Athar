package eval_test

import (
	"strings"
	"testing"

	"github.com/Athar-HQ/Athar/cli/internal/eval"
	"github.com/Athar-HQ/Athar/cli/internal/probe"
	"github.com/Athar-HQ/Athar/cli/internal/rule"
)

// rawRule compiles a rule from its probes, detection and tests, and sets
// eval.RawHTTP to the scanner's parser, as the CLI does.
func rawRule(t *testing.T, lines ...string) *eval.Compiled {
	t.Helper()
	old := eval.RawHTTP
	eval.RawHTTP = probe.HTTPFields
	t.Cleanup(func() { eval.RawHTTP = old })
	src := "title: Example\nid: 0ce69e91-baee-4475-81ee-4b8eca1a6c3b\nstatus: experimental\n" +
		"target: { protocol: http }\nidentifies: { product: Example, category: web-server }\nconfidence: high\n" +
		strings.Join(lines, "\n") + "\n"
	r, err := rule.Parse([]byte(src), "raw.yml")
	if err != nil {
		t.Fatal(err)
	}
	c, _, err := eval.Compile(r)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func check(t *testing.T, res []eval.TestResult, want []bool) {
	t.Helper()
	if len(res) != len(want) {
		t.Fatalf("got %d results, want %d", len(res), len(want))
	}
	for i, r := range res {
		if r.Passed != want[i] {
			t.Errorf("test %q: passed = %v, want %v (%s)", r.Name, r.Passed, want[i], r.Detail)
		}
	}
}

// A raw response goes through the scanner's field extraction: the title is
// entity-decoded, headers become fields and the head is kept as received.
func TestRunTestsRaw(t *testing.T) {
	c := rawRule(t,
		"detection:",
		"  sel:",
		"    http.title: 'Tom & Jerry Console'",
		"    http.status_code: 200",
		"    http.headers.server|contains: nginx",
		`    http.headers_raw|contains: "nginx/1.24\r\nX-Powered-By: Example\r\n\r\n"`,
		`    http.body|endswith: "</html>\n"`,
		"  condition: sel",
		"extract:",
		`  who: { field: http.title, regex: '^(?P<who>\w+)' }`,
		"tests:",
		"  - name: LF head in a block scalar",
		"    expect: match",
		"    extracted: { who: Tom }",
		"    raw: |",
		"      HTTP/1.1 200 OK",
		"      Server: nginx/1.24",
		"      X-Powered-By: Example",
		"",
		"      <html><head><title>Tom &amp; Jerry",
		"        Console</title></head></html>",
		"  - name: CRLF head in a double-quoted string",
		"    expect: match",
		`    raw: "HTTP/1.1 200 OK\r\nServer: nginx/1.24\r\nX-Powered-By: Example\r\n\r\n<title>Tom &#38; Jerry Console</title></html>\n"`,
		"  - name: chunked body",
		"    expect: match",
		`    raw: "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nServer: nginx/1.24\r\nX-Powered-By: Example\r\n\r\n1e\r\n<title>Tom &amp; Jerry Console\r\n10\r\n</title></html>\n\r\n0\r\n\r\n"`,
		"  - name: the text is on the page, but not in the title",
		"    expect: no_match",
		"    raw: |",
		"      HTTP/1.1 200 OK",
		"      Server: nginx/1.24",
		"      X-Powered-By: Example",
		"",
		"      <html><body><h1>Tom & Jerry Console</h1></body></html>",
		"  - name: wrong expectation",
		"    expect: no_match",
		`    raw: "HTTP/1.1 200 OK\r\nServer: nginx/1.24\r\nX-Powered-By: Example\r\n\r\n<title>Tom &#38; Jerry Console</title></html>\n"`,
	)
	check(t, c.RunTests(), []bool{true, true, true, true, false})
}

func TestRunTestsRawBroken(t *testing.T) {
	c := rawRule(t,
		"detection:",
		"  sel: { http.title: Example }",
		"  condition: sel",
		"tests:",
		"  - name: no status line",
		"    expect: match",
		"    raw: '<title>Example</title>'",
		"  - name: bad status code",
		"    expect: no_match",
		"    raw: |",
		"      HTTP/1.1 OK",
		"",
		"      <title>Example</title>",
	)
	res := c.RunTests()
	check(t, res, []bool{false, false})
	if want := "raw: not an HTTP response"; res[0].Detail != want {
		t.Errorf("detail = %q, want %q", res[0].Detail, want)
	}
	if !strings.HasPrefix(res[1].Detail, "raw: ") {
		t.Errorf("detail = %q, want the parser's reason after \"raw: \"", res[1].Detail)
	}

	// Without a parser a raw test fails; it is not skipped.
	eval.RawHTTP = nil
	res = c.RunTests()
	check(t, res, []bool{false, false})
	if !strings.HasPrefix(res[0].Detail, "raw: ") {
		t.Errorf("detail = %q", res[0].Detail)
	}
}

// Fields under response are added to the ones derived from raw and win.
func TestRunTestsRawWithResponse(t *testing.T) {
	c := rawRule(t,
		"detection:",
		"  sel:",
		"    http.title: Example",
		"    http.favicon.mmh3: -576220750",
		"    tls.cert.subject.cn: example.org",
		"  condition: sel",
		"tests:",
		"  - name: raw alone has no favicon and no certificate",
		"    expect: no_match",
		"    raw: &page |",
		"      HTTP/1.1 200 OK",
		"",
		"      <title>Example</title>",
		"  - name: response adds them",
		"    expect: match",
		"    raw: *page",
		"    response: { http.favicon.mmh3: -576220750, tls.cert.subject.cn: example.org }",
		"  - name: response wins over raw",
		"    expect: no_match",
		"    raw: *page",
		"    response: { http.favicon.mmh3: -576220750, tls.cert.subject.cn: example.org, http.title: Other }",
		"  - name: unknown field next to raw",
		"    expect: match",
		"    raw: *page",
		"    response: { http.favicon.mmh3: -576220750, tls.cert.subject.cn: example.org, http.titel: Example }",
	)
	check(t, c.RunTests(), []bool{true, true, true, false})
}

func TestRunTestsRawUnderProbes(t *testing.T) {
	const sum = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad" // sha256("abc")
	c := rawRule(t,
		"probes:",
		"  css: { protocol: http, request: { path: /app.css } }",
		"detection:",
		"  sel:",
		"    probe: css",
		"    http.status_code: 200",
		"    http.body.sha256: "+sum,
		"  condition: sel",
		"tests:",
		"  - name: the file as served",
		"    expect: match",
		"    probes:",
		"      css:",
		`        raw: "HTTP/1.1 200 OK\r\nContent-Type: text/css\r\n\r\nabc"`,
		"  - name: a block scalar ends the body with a newline",
		"    expect: no_match",
		"    probes:",
		"      css:",
		"        raw: |",
		"          HTTP/1.1 200 OK",
		"",
		"          abc",
		"  - name: a block scalar with the newline stripped",
		"    expect: match",
		"    probes:",
		"      css:",
		"        raw: |-",
		"          HTTP/1.1 200 OK",
		"",
		"          abc",
		"  - name: a field next to raw wins",
		"    expect: no_match",
		"    probes:",
		"      css:",
		`        raw: "HTTP/1.1 200 OK\r\n\r\nabc"`,
		"        http.status_code: 404",
		"  - name: raw for the baseline is not the probe's response",
		"    expect: no_match",
		`    raw: "HTTP/1.1 200 OK\r\n\r\nabc"`,
		"  - name: broken raw under a probe",
		"    expect: no_match",
		"    probes: { css: { raw: 'abc' } }",
	)
	res := c.RunTests()
	check(t, res, []bool{true, true, true, true, true, false})
	if want := "probe css: raw: not an HTTP response"; res[5].Detail != want {
		t.Errorf("detail = %q, want %q", res[5].Detail, want)
	}
}
