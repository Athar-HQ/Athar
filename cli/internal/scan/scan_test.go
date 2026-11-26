package scan

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/Athar-HQ/Athar/cli/internal/eval"
	"github.com/Athar-HQ/Athar/cli/internal/output"
	"github.com/Athar-HQ/Athar/cli/internal/probe"
	"github.com/Athar-HQ/Athar/cli/internal/rule"
)

// repoRules compiles the rules shipped in this repository.
func repoRules(t *testing.T) []*eval.Compiled {
	t.Helper()
	files, err := rule.Files([]string{"../../../rules"})
	if err != nil {
		t.Fatal(err)
	}
	var out []*eval.Compiled
	for _, f := range files {
		r, err := rule.Load(f)
		if err != nil {
			t.Fatal(err)
		}
		c, _, err := eval.Compile(r)
		if err != nil {
			t.Fatal(err)
		}
		out = append(out, c)
	}
	return out
}

func compileRule(t *testing.T, src string) *eval.Compiled {
	t.Helper()
	r, err := rule.Parse([]byte(src), "inline.yml")
	if err != nil {
		t.Fatal(err)
	}
	c, _, err := eval.Compile(r)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func page(title string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("<html><title>" + title + "</title><body><a href=\"/function/tasks\">x</a></body></html>"))
	})
}

func scanOne(t *testing.T, s *Scanner, rawURL string) []output.Record {
	t.Helper()
	u, _ := url.Parse(rawURL)
	tg, err := probe.ParseTarget(u.Host)
	if err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	st := s.Run(context.Background(), []probe.Target{tg}, output.NewJSON(&buf))
	if st.Open != 1 {
		t.Fatalf("open = %d, want 1", st.Open)
	}
	var recs []output.Record
	for _, line := range strings.Split(strings.TrimSpace(buf.String()), "\n") {
		if line == "" {
			continue
		}
		var r output.Record
		if err := json.Unmarshal([]byte(line), &r); err != nil {
			t.Fatalf("bad JSON line %q: %v", line, err)
		}
		recs = append(recs, r)
	}
	if int64(len(recs)) != st.Matches {
		t.Errorf("stats say %d matches, output has %d", st.Matches, len(recs))
	}
	return recs
}

func opts() Options {
	return Options{Ports: []int{80}, Concurrency: 4, PerHost: 2, Rate: 0, Timeout: 2 * time.Second, UserAgent: "athar-test"}
}

// A rebrand matches the family and the rebrands variant; the variant
// replaces the family record and keeps the brand it extracts.
func TestRebrandMatchExtractsBrand(t *testing.T) {
	srv := httptest.NewServer(page("NKW — Autonomous Penetration Testing Console"))
	defer srv.Close()

	recs := scanOne(t, New(repoRules(t), opts()), srv.URL)
	if len(recs) != 1 {
		t.Fatalf("got %d records: %+v", len(recs), recs)
	}
	r := recs[0]
	// The author is in every record: DRL 1.1 asks match messages to keep it.
	if r.Rule != "7b24901b-6476-48a0-9d08-a28544384844" || r.Extracted["brand"] != "NKW" || r.Family != "artex" || r.Author != "Gameel Ali (@MalGamy12)" {
		t.Errorf("record = %+v", r)
	}
	if r.Target != strings.TrimPrefix(srv.URL, "http://") || r.TLS || r.IP != "" {
		t.Errorf("target fields = %q tls=%v ip=%q", r.Target, r.TLS, r.IP)
	}
}

func TestVariantSupersedesFamily(t *testing.T) {
	srv := httptest.NewServer(page("ARTEX — Autonomous Penetration Testing Console"))
	defer srv.Close()

	recs := scanOne(t, New(repoRules(t), opts()), srv.URL)
	if len(recs) != 1 || recs[0].Product != "ARTEX" {
		t.Fatalf("want only the ARTEX variant, got %+v", recs)
	}
}

func TestNoMatch(t *testing.T) {
	srv := httptest.NewServer(page("Penetration Testing Services | Example Corp"))
	defer srv.Close()
	if recs := scanOne(t, New(repoRules(t), opts()), srv.URL); len(recs) != 0 {
		t.Errorf("unexpected records: %+v", recs)
	}
}

const tlsRule = `
title: Acme TLS
id: 7d2f9a4e-3b1c-4e8a-9f60-2c5d8e1b7a43
status: experimental
target: { protocol: http, tls: %s }
detection:
  sel:
    tls.cert.subject.o: Acme Co
    http.body|contains: /function/tasks
  condition: sel
identifies: { product: Acme, category: web-server }
confidence: medium
`

func TestTLSConstraint(t *testing.T) {
	srv := httptest.NewTLSServer(page("whatever"))
	defer srv.Close()

	for mode, want := range map[string]int{"auto": 1, "required": 1, "none": 0} {
		c := compileRule(t, strings.Replace(tlsRule, "%s", mode, 1))
		recs := scanOne(t, New([]*eval.Compiled{c}, opts()), srv.URL)
		if len(recs) != want {
			t.Errorf("tls: %s: got %d records, want %d", mode, len(recs), want)
		}
		if len(recs) == 1 && !recs[0].TLS {
			t.Errorf("tls: %s: record not marked TLS", mode)
		}
	}
}

const plainRule = `
title: Plain only
id: 0c9e5b0a-6f0d-4c57-9a3e-5d1b6f2a8c11
status: experimental
target: { protocol: http, tls: none }
detection:
  sel:
    http.status_code|exists: true
  condition: sel
identifies: { product: Plain, category: web-server }
confidence: low
`

// ruleIDs returns the ids of the rules that matched, sorted.
func ruleIDs(recs []output.Record) string {
	var ids []string
	for _, r := range recs {
		ids = append(ids, r.Rule)
	}
	sort.Strings(ids)
	return strings.Join(ids, " ")
}

// A tls: none rule is never evaluated on a service that speaks TLS, whether
// or not another loaded rule needs TLS. Loaded alone it used to skip the
// handshake and match the server's plaintext "400 Bad Request".
func TestTLSNoneWhateverElseIsLoaded(t *testing.T) {
	tlsSrv := httptest.NewTLSServer(page("whatever"))
	defer tlsSrv.Close()
	plainSrv := httptest.NewServer(page("whatever"))
	defer plainSrv.Close()

	none := compileRule(t, plainRule)
	auto := compileRule(t, strings.Replace(tlsRule, "%s", "auto", 1))
	for name, rules := range map[string][]*eval.Compiled{"alone": {none}, "with a TLS rule": {none, auto}} {
		s := New(rules, opts())
		for _, r := range scanOne(t, s, tlsSrv.URL) {
			if r.Rule == none.Rule.ID {
				t.Errorf("%s: tls: none rule matched a TLS service", name)
			}
		}
		if got := ruleIDs(scanOne(t, s, plainSrv.URL)); got != none.Rule.ID {
			t.Errorf("%s: plaintext service matched %q, want the tls: none rule", name, got)
		}
	}
}

// bannerServer speaks first, like SSH or FTP, and answers nothing.
func bannerServer(t *testing.T, banner string) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				c.Write([]byte(banner))
				c.SetReadDeadline(time.Now().Add(3 * time.Second))
				c.Read(make([]byte, 1024))
			}()
		}
	}()
	return "http://" + ln.Addr().String()
}

const fieldRule = `
title: Field rule
id: %s
status: experimental
target: { protocol: %s }
detection:
  sel:
    %s
  condition: sel
identifies: { product: X, category: web-server }
confidence: low
`

// A rule gets the fields it reads whatever its target.protocol says and
// whatever else is loaded: the banner for an http rule, GET / for a tcp rule.
func TestFieldsCollectedWhateverElseIsLoaded(t *testing.T) {
	ftp := bannerServer(t, "220 Acme FTP ready\r\n")
	ssh := bannerServer(t, "SSH-2.0-AcmeSSH_1.0\r\n")
	web := httptest.NewServer(page("whatever"))
	defer web.Close()

	// A rule of the other kind that never matches.
	const otherID = "5a1d3c7e-2b4f-4a6d-8e9f-0a1b2c3d4e5f"
	other := map[string]*eval.Compiled{
		"http": compileRule(t, fmt.Sprintf(fieldRule, otherID, "tcp", "service.port|exists: false")),
		"tcp":  compileRule(t, fmt.Sprintf(fieldRule, otherID, "http", "service.port|exists: false")),
	}
	for _, tt := range []struct{ name, protocol, selection, server string }{
		{"service.banner in an http rule", "http", "service.banner|contains: 'Acme FTP'", ftp},
		{"keywords in an http rule", "http", "- 'acme ftp'", ftp},
		{"ssh.banner in an http rule", "http", "ssh.banner|contains: AcmeSSH", ssh},
		{"service.protocol ssh in an http rule", "http", "service.protocol: ssh", ssh},
		{"service.protocol http in a tcp rule", "tcp", "service.protocol: http", web.URL},
		{"http.title in a tcp rule", "tcp", "http.title: whatever", web.URL},
	} {
		c := compileRule(t, fmt.Sprintf(fieldRule, "9b8a7c6d-5e4f-4a3b-8c2d-1e0f9a8b7c6d", tt.protocol, tt.selection))
		o := opts()
		o.Timeout = 500 * time.Millisecond
		for name, rules := range map[string][]*eval.Compiled{"alone": {c}, "with another rule": {c, other[tt.protocol]}} {
			if got := ruleIDs(scanOne(t, New(rules, o), tt.server)); got != c.Rule.ID {
				t.Errorf("%s, %s: matched %q, want the rule", tt.name, name, got)
			}
		}
	}
}

// The prober offers no ALPN protocol, so none is negotiated and tls.alpn is
// never set. A rule that reads it is warned about, like JARM.
func TestWarnsAboutALPN(t *testing.T) {
	const id = "9b8a7c6d-5e4f-4a3b-8c2d-1e0f9a8b7c6d"
	c := compileRule(t, fmt.Sprintf(fieldRule, id, "http", "tls.alpn: http/1.1"))
	w := strings.Join(New([]*eval.Compiled{c}, opts()).Warnings(), "\n")
	if !strings.Contains(w, "does not collect tls.alpn") {
		t.Errorf("warnings = %q", w)
	}
	for _, f := range []string{"tls.version", "tls.cipher"} {
		c := compileRule(t, fmt.Sprintf(fieldRule, id, "http", f+"|exists: true"))
		if w := New([]*eval.Compiled{c}, opts()).Warnings(); len(w) != 0 {
			t.Errorf("%s is collected, but: %v", f, w)
		}
	}
}

func TestNeedsAndWarnings(t *testing.T) {
	s := New(repoRules(t), opts())
	if n := s.Needs(); !n.HTTP || !n.Favicon || n.Banner {
		t.Errorf("needs for the ARTEX rules = %+v", n)
	}
	// The ARTEX frontend files rule fetches files with custom probes, which
	// are only sent with -probes.
	if w := s.Warnings(); len(w) != 1 || !strings.Contains(w[0], "only sent with -probes") {
		t.Errorf("warnings = %v", w)
	}
	withProbes := opts()
	withProbes.Probes = true
	if w := New(repoRules(t), withProbes).Warnings(); len(w) != 0 {
		t.Errorf("warnings with -probes = %v", w)
	}

	jarm := compileRule(t, `
title: JARM only
id: 7d2f9a4e-3b1c-4e8a-9f60-2c5d8e1b7a43
status: experimental
target: { protocol: tcp }
probes:
  hello: { protocol: tcp, send: 'hi' }
detection:
  sel:
    tls.jarm: 07d14d16d21d21d07c42d41d00041d24a458a375eef0c576d23a7bab9a9fb1
  condition: sel
identifies: { product: X, category: c2 }
confidence: low
`)
	s = New([]*eval.Compiled{jarm}, opts())
	if n := s.Needs(); !n.Banner || n.HTTP {
		t.Errorf("needs for a tcp rule = %+v", n)
	}
	w := strings.Join(s.Warnings(), "\n")
	if !strings.Contains(w, "does not collect tls.jarm") || !strings.Contains(w, "only sent with -probes") {
		t.Errorf("warnings = %q", w)
	}
}

func TestPerHostLimitAndClosedPorts(t *testing.T) {
	srv := httptest.NewServer(page("NKW — Autonomous Penetration Testing Console"))
	defer srv.Close()
	u, _ := url.Parse(srv.URL)
	open, _ := strconv.Atoi(u.Port())

	// Two closed ports next to the open one.
	var closed []int
	for range 2 {
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		closed = append(closed, ln.Addr().(*net.TCPAddr).Port)
		ln.Close()
	}
	o := opts()
	o.Ports = append([]int{open}, closed...)
	o.PerHost = 1
	o.Rate = 50
	s := New(repoRules(t), o)
	tg, _ := probe.ParseTarget("127.0.0.1")
	var buf bytes.Buffer
	st := s.Run(context.Background(), []probe.Target{tg}, output.NewJSON(&buf))
	if st.Checks != 3 || st.Open != 1 || st.Matches != 1 {
		t.Errorf("stats = %+v\n%s", st, buf.String())
	}
}

func TestCancel(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	tg, _ := probe.ParseTarget("127.0.0.0/24")
	st := New(repoRules(t), opts()).Run(ctx, []probe.Target{tg}, output.NewJSON(&bytes.Buffer{}))
	if !st.Interrupted || st.Open != 0 {
		t.Errorf("stats after cancel = %+v", st)
	}
}

// A port that accepts connections but drops every request, like a proxy with
// no backend, is reported as open with no response.
func TestLogSilentPort(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				c.Read(make([]byte, 1024))
				c.Close()
			}()
		}
	}()
	silent := ln.Addr().String()

	srv := httptest.NewServer(page("Login"))
	defer srv.Close()
	web := strings.TrimPrefix(srv.URL, "http://")

	var log bytes.Buffer
	o := opts()
	o.Log = &log
	s := New(repoRules(t), o)
	for _, target := range []string{silent, web} {
		tg, err := probe.ParseTarget(target)
		if err != nil {
			t.Fatal(err)
		}
		s.Run(context.Background(), []probe.Target{tg}, output.NewJSON(&bytes.Buffer{}))
	}
	want := "open " + silent + " no response (tried TLS, HTTP)\nopen " + web + " http 200 \"Login\"\n"
	if log.String() != want {
		t.Errorf("log:\n got %q\nwant %q", log.String(), want)
	}
}
