package scan

import (
	"bytes"
	"context"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
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
	if r.Rule != "7b24901b-6476-48a0-9d08-a28544384844" || r.Extracted["brand"] != "NKW" || r.Family != "artex" {
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

func TestNeedsAndWarnings(t *testing.T) {
	s := New(repoRules(t), opts())
	if n := s.Needs(); !n.HTTP || !n.Favicon || !n.TLS || n.Banner {
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
