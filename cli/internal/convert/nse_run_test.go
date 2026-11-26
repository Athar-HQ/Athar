package convert

import (
	"bufio"
	"bytes"
	"compress/flate"
	"compress/gzip"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"encoding/xml"
	"fmt"
	"hash/crc32"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Athar-HQ/Athar/cli/internal/eval"
	"github.com/Athar-HQ/Athar/cli/internal/output"
	"github.com/Athar-HQ/Athar/cli/internal/probe"
	"github.com/Athar-HQ/Athar/cli/internal/rule"
	"github.com/Athar-HQ/Athar/cli/internal/scan"
)

// These tests run athar.nse in Nmap against local servers. They need the
// nmap binary and are skipped without it, and with -short.

// TestNSERulesRun checks every rule in rules/ against servers that answer
// like the rules' tests. An exact conversion must give each test's result
// and extracted values; a superset one must at least find every match.
func TestNSERulesRun(t *testing.T) {
	bin := nmapBin(t)
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
	nseCheck(t, bin, rules, nil, false)
}

// TestNSEFeaturesRun checks conversions the repository's rules don't use
// yet, strictly.
func TestNSEFeaturesRun(t *testing.T) {
	bin := nmapBin(t)
	rules, icon := featureRules(t)
	port := func(u string) int {
		p, _ := url.Parse(u)
		n, _ := strconv.Atoi(p.Port())
		return n
	}
	const hashes = "22222222-2222-4222-8222-222222222222"
	extra := []nseCase{
		{rule: hashes, test: "hashes: same favicon and body", port: port(serveIconPage(t, icon)), expect: true},
		{rule: hashes, test: "hashes: other favicon", port: port(serveIconPage(t, []byte("other"))), expect: false},
	}
	nseCheck(t, bin, rules, extra, true)
}

// TestNSEMatchesScan runs athar scan and athar.nse on the same raw responses
// and compares what they report: which rules match, and every field value,
// read back through extract.
func TestNSEMatchesScan(t *testing.T) {
	bin := nmapBin(t)
	servers := diffServers(t)
	var ports []int
	for _, p := range servers {
		ports = append(ports, p)
	}
	// Where athar scan matches, so that agreement is not just both missing.
	plain := []string{"entities and headers", "chunked gzip", "HTTP/1.0 until close", "bare LF", "no body", "escaped favicon path", "custom probe",
		"gzip corrupt", "gzip truncated", "gzip header fields", "gzip header CRC",
		"favicon link without a path", "favicon link without a hierarchy", "headers as received"}
	expect := map[string][]string{
		"diff headers as received": {"headers as received"},
		"diff lists":               {"entities and headers", "TLS"},
		"diff fold":                {"chunked gzip"},
		"diff wildcard and regex":  {"entities and headers"},
		"diff keyword and numbers": {"entities and headers", "chunked gzip", "bare LF"},
		"diff absent title":        {"no body", "rejected header", "banner", "gzip corrupt"},
		"diff custom probe":        {"custom probe"},
		"diff TLS required":        {"TLS"},
		"diff TLS none":            plain,
		"diff banner":              {"banner"},
	}
	for _, group := range []struct {
		name  string
		rules []*rule.Rule
	}{
		{"http", diffRules(t, false)},
		{"with banner", diffRules(t, true)},
	} {
		t.Run(group.name, func(t *testing.T) {
			want := scanRecords(t, group.rules, ports)
			got := runNSE(t, bin, group.rules, ports, "athar.probes", "athar.timeout=1s")
			for name, port := range servers {
				for _, r := range group.rules {
					w, wok := want[port][r.ID]
					g, gok := got[port][r.ID]
					expected := r.Title == "diff fields"
					for _, s := range expect[r.Title] {
						expected = expected || s == name
					}
					if wok != expected {
						t.Errorf("%s, %s: athar scan matched=%v, want %v", name, r.Title, wok, expected)
					}
					if wok != gok {
						t.Errorf("%s, %s: athar scan matched=%v, athar.nse matched=%v", name, r.Title, wok, gok)
						continue
					}
					if wok && !reflect.DeepEqual(w.extracted, g.extracted) {
						for k := range union(w.extracted, g.extracted) {
							a, b := w.extracted[k], g.extracted[k]
							if a == b || (name == "gzip truncated" && truncatedAlike(k, a, b)) {
								continue
							}
							t.Errorf("%s, %s, %s:\nathar scan %q\nathar.nse  %q", name, r.Title, k, a, b)
						}
					}
				}
			}
		})
	}
}

// TestNSERuleAloneMatchesScan loads one rule at a time: what a rule matches
// must not depend on the other rules loaded. Alone, a tls: none rule used to
// keep both scanners from trying TLS, so it matched the plaintext "400 Bad
// Request" of a TLS server, and an http rule never got the banner it reads.
func TestNSERuleAloneMatchesScan(t *testing.T) {
	bin := nmapBin(t)
	srv := httptest.NewTLSServer(http.NotFoundHandler())
	defer srv.Close()
	u, _ := url.Parse(srv.URL)
	tlsPort, _ := strconv.Atoi(u.Port())
	ftpPort := rawServer(t, nil, nil, "220 Acme FTP ready\r\n")

	for _, tt := range []struct {
		src  string
		port int // where the rule must match; 0 for nowhere
	}{{`
title: alone TLS none
id: 10000000-0000-4000-8000-0000000000a1
target: {protocol: http, tls: none}
detection:
  selection:
    http.status_code|exists: true
  condition: selection
`, 0}, {`
title: alone banner
id: 10000000-0000-4000-8000-0000000000a2
target: {protocol: http}
detection:
  selection:
    service.banner|contains: 'Acme FTP'
  condition: selection
`, ftpPort}, {`
title: alone keyword
id: 10000000-0000-4000-8000-0000000000a3
target: {protocol: http}
detection:
  keywords:
    - 'acme ftp'
  condition: keywords
`, ftpPort}} {
		r := parse(t, "alone.yml", tt.src)
		rules, ports := []*rule.Rule{r}, []int{tlsPort, ftpPort}
		want := scanRecords(t, rules, ports)
		got := runNSE(t, bin, rules, ports, "athar.timeout=1s")
		for _, port := range ports {
			_, wok := want[port][r.ID]
			_, gok := got[port][r.ID]
			if expected := port == tt.port; wok != expected || gok != expected {
				t.Errorf("%s, port %d: athar scan matched=%v, athar.nse matched=%v, want %v", r.Title, port, wok, gok, expected)
			}
		}
	}
}

// truncatedAlike accepts the one difference between Go's flate and zlib:
// at the end of a truncated stream, zlib can emit a few more bytes, because
// Go reads ahead before it decodes the last symbols.
func truncatedAlike(field, a, b string) bool {
	switch field {
	case "body":
		return strings.HasPrefix(b, a) && len(b)-len(a) <= 8
	case "body_mmh3", "body_sha256":
		return true
	}
	return false
}

func union(a, b map[string]string) map[string]bool {
	out := map[string]bool{}
	for k := range a {
		out[k] = true
	}
	for k := range b {
		out[k] = true
	}
	return out
}

// TestNSEOutputLineFeed checks that an extracted value can't add lines to
// Nmap's readable output. Nmap escapes other control characters itself but
// prints a line feed as a new line, which could read like another match.
// The XML output keeps the value.
func TestNSEOutputLineFeed(t *testing.T) {
	bin := nmapBin(t)
	r := parse(t, "linefeed.yml", `
title: line feed in extract
id: 10000000-0000-4000-8000-0000000000f1
target: {protocol: http}
detection:
  selection:
    http.title: 'line feed test'
  condition: selection
extract:
  ver: {field: http.body, regex: '(?s)ver=(.*)END'}
`)
	res, err := Convert(r, nseTarget)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, NSERulesDir), 0o755); err != nil {
		t.Fatal(err)
	}
	for name, data := range map[string]string{"athar.nse": NSEScript, filepath.Join(NSERulesDir, res.TemplateID+".lua"): res.Template} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(data), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	port := rawServer(t, map[string]string{"/": httpResponse("HTTP/1.1 200 OK\r\n",
		"<title>line feed test</title>ver=1.0\n  Fake Rule:\n    rule:\tforgedEND")}, nil, "")
	xmlFile := filepath.Join(dir, "nmap.xml")
	text, err := exec.Command(bin, "-sT", "-Pn", "-n", "-p", strconv.Itoa(port), "--script", filepath.Join(dir, "athar.nse"), "-oX", xmlFile, "127.0.0.1").CombinedOutput()
	if err != nil {
		t.Fatalf("nmap: %v\n%s", err, text)
	}
	if want := `ver: 1.0\x0A  Fake Rule:\x0A    rule:\x09forged` + "\n"; !strings.Contains(string(text), want) || strings.Contains(string(text), "|   Fake Rule:") {
		t.Errorf("readable output:\n%s\nwant a line with %q", text, want)
	}
	data, err := os.ReadFile(xmlFile)
	if err != nil {
		t.Fatal(err)
	}
	if want := `<elem key="ver">1.0&#xa;  Fake Rule:&#xa;    rule:&#x9;forged</elem>`; !strings.Contains(string(data), want) {
		t.Errorf("XML output:\n%s\nwant %s", data, want)
	}
}

func nmapBin(t *testing.T) string {
	t.Helper()
	bin, err := exec.LookPath("nmap")
	if err != nil {
		if os.Getenv("ATHAR_REQUIRE_SCANNERS") != "" {
			t.Fatal("nmap not installed, but ATHAR_REQUIRE_SCANNERS is set")
		}
		t.Skip("nmap not installed")
	}
	if testing.Short() {
		t.Skip("runs nmap")
	}
	return bin
}

type nseCase struct {
	rule, test string // rule id and test name
	port       int
	expect     bool
	extracted  map[string]string
	fid        Fidelity
}

// nseCheck serves the rules' tests, runs Nmap once over all of them and
// compares. strict also holds approximate conversions to the expected
// result.
func nseCheck(t *testing.T, bin string, rules []*rule.Rule, cases []nseCase, strict bool) {
	t.Helper()
	fids := map[string]Fidelity{}
	skipped := 0
	for _, r := range rules {
		if _, _, err := eval.Compile(r); err != nil {
			t.Fatalf("%s: %v", r.Path, err)
		}
		res, err := Convert(r, nseTarget)
		if err != nil {
			t.Fatalf("%s: %v", r.Path, err)
		}
		if res.Template == "" {
			continue
		}
		fids[r.ID] = res.Fidelity
		for _, tc := range r.Tests {
			srv, ok := serveTest(t, r, tc)
			if !ok {
				skipped++
				continue
			}
			u, _ := url.Parse(srv)
			port, _ := strconv.Atoi(u.Port())
			cases = append(cases, nseCase{r.ID, filepath.Base(r.Path) + ": " + tc.Name, port, tc.Expect == "match", tc.Extracted, 0})
		}
	}
	var ports []int
	for i := range cases {
		cases[i].fid = fids[cases[i].rule]
		ports = append(ports, cases[i].port)
	}
	got := runNSE(t, bin, rules, ports, "athar.probes")
	matches := 0
	for _, c := range cases {
		m, hit := got[c.port][c.rule]
		if hit {
			matches++
		}
		hard := strict || c.fid == Exact || (c.fid == Superset && c.expect)
		if hit != c.expect {
			if hard {
				t.Errorf("%s (%s): athar.nse matched=%v, test expects %v", c.test, c.fid, hit, c.expect)
			} else {
				t.Logf("%s (%s): athar.nse matched=%v, test expects %v", c.test, c.fid, hit, c.expect)
			}
			continue
		}
		for name, want := range c.extracted {
			if m.extracted[name] != want && hard {
				t.Errorf("%s: extract %s: want %q, athar.nse extracted %q", c.test, name, want, m.extracted[name])
			}
		}
	}
	if matches == 0 {
		t.Errorf("athar.nse matched nothing; the harness is broken")
	}
	t.Logf("%d test responses checked with nmap (%d matches), %d skipped", len(cases), matches, skipped)
}

// nseMatch is one rule athar.nse or athar scan reported on one port.
type nseMatch struct {
	author    string
	extracted map[string]string
}

// runNSE writes athar.nse and the rules' data files, runs Nmap once against
// 127.0.0.1 on the ports and returns the matches per port by rule id.
func runNSE(t *testing.T, bin string, rules []*rule.Rule, ports []int, args ...string) map[int]map[string]nseMatch {
	t.Helper()
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, NSERulesDir), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "athar.nse"), []byte(NSEScript), 0o644); err != nil {
		t.Fatal(err)
	}
	titles := map[string]string{} // title -> rule id
	seen := map[string]string{}
	for _, r := range rules {
		res, err := Convert(r, nseTarget)
		if err != nil {
			t.Fatalf("%s: %v", r.Path, err)
		}
		if res.Template == "" {
			continue
		}
		if other, dup := seen[res.TemplateID]; dup {
			t.Fatalf("%s and %s both write %s.lua", other, r.Path, res.TemplateID)
		}
		seen[res.TemplateID] = r.Path
		titles[r.Title] = r.ID
		if err := os.WriteFile(filepath.Join(dir, NSERulesDir, res.TemplateID+".lua"), []byte(res.Template), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	var pl []string
	for _, p := range ports {
		pl = append(pl, strconv.Itoa(p))
	}
	out := filepath.Join(dir, "nmap.xml")
	cmdArgs := []string{"-sT", "-Pn", "-n", "-p", strings.Join(pl, ","), "--script", filepath.Join(dir, "athar.nse"), "-oX", out}
	if len(args) > 0 {
		cmdArgs = append(cmdArgs, "--script-args", strings.Join(args, ","))
	}
	cmdArgs = append(cmdArgs, "127.0.0.1")
	if b, err := exec.Command(bin, cmdArgs...).CombinedOutput(); err != nil {
		t.Fatalf("nmap: %v\n%s", err, b)
	}
	data, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	type elem struct {
		Key   string `xml:"key,attr"`
		Value string `xml:",chardata"`
	}
	type table struct {
		Key    string  `xml:"key,attr"`
		Elems  []elem  `xml:"elem"`
		Tables []table `xml:"table"`
	}
	var run struct {
		Hosts []struct {
			Ports []struct {
				ID      int `xml:"portid,attr"`
				Scripts []struct {
					ID     string  `xml:"id,attr"`
					Output string  `xml:"output,attr"`
					Tables []table `xml:"table"`
				} `xml:"script"`
			} `xml:"ports>port"`
		} `xml:"host"`
	}
	if err := xml.Unmarshal(data, &run); err != nil {
		t.Fatalf("nmap XML: %v", err)
	}
	got := map[int]map[string]nseMatch{}
	for _, h := range run.Hosts {
		for _, p := range h.Ports {
			for _, s := range p.Scripts {
				if s.ID != "athar" {
					continue
				}
				if strings.Contains(s.Output, "ERROR") && len(s.Tables) == 0 {
					t.Errorf("port %d: %s", p.ID, s.Output)
				}
				for _, tb := range s.Tables {
					m := nseMatch{extracted: map[string]string{}}
					id := ""
					for _, e := range tb.Elems {
						switch e.Key {
						case "rule":
							id = e.Value
						case "author":
							m.author = unprotect(e.Value)
						}
					}
					for _, sub := range tb.Tables {
						if sub.Key == "extracted" {
							for _, e := range sub.Elems {
								m.extracted[e.Key] = unprotect(e.Value)
							}
						}
					}
					if id == "" {
						id = titles[tb.Key]
					}
					if got[p.ID] == nil {
						got[p.ID] = map[string]nseMatch{}
					}
					got[p.ID][id] = m
				}
			}
		}
	}
	// The DRL 1.1 asks every message about a match to name the author.
	for _, r := range rules {
		for port, ms := range got {
			if m, ok := ms[r.ID]; ok && m.author != r.Author {
				t.Errorf("port %d, %s: author %q, want %q", port, r.Title, m.author, r.Author)
			}
		}
	}
	return got
}

var protectedByte = regexp.MustCompile(`\\x[0-9A-Fa-f]{2}`)

// unprotect undoes Nmap's XML output escaping, which writes bytes that are
// not printable ASCII as \xHH.
func unprotect(s string) string {
	return protectedByte.ReplaceAllStringFunc(s, func(m string) string {
		b, _ := strconv.ParseUint(m[2:], 16, 8)
		return string([]byte{byte(b)})
	})
}

type recordSink struct {
	mu   sync.Mutex
	recs []output.Record
}

func (s *recordSink) Write(r output.Record) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.recs = append(s.recs, r)
	return nil
}

// scanRecords runs athar scan's scanner with custom probes on the ports.
func scanRecords(t *testing.T, rules []*rule.Rule, ports []int) map[int]map[string]nseMatch {
	t.Helper()
	var compiled []*eval.Compiled
	for _, r := range rules {
		c, _, err := eval.Compile(r)
		if err != nil {
			t.Fatalf("%s: %v", r.Path, err)
		}
		compiled = append(compiled, c)
	}
	s := scan.New(compiled, scan.Options{
		Ports: ports, Concurrency: 16, PerHost: 16,
		Connect: time.Second, Timeout: time.Second,
		Probes: true, UserAgent: "athar-test",
	})
	target, err := probe.ParseTarget("127.0.0.1")
	if err != nil {
		t.Fatal(err)
	}
	sink := &recordSink{}
	s.Run(context.Background(), []probe.Target{target}, sink)
	got := map[int]map[string]nseMatch{}
	for _, rec := range sink.recs {
		_, ps, _ := net.SplitHostPort(rec.Target)
		port, _ := strconv.Atoi(ps)
		if got[port] == nil {
			got[port] = map[string]nseMatch{}
		}
		ex := rec.Extracted
		if ex == nil {
			ex = map[string]string{}
		}
		got[port][rec.Rule] = nseMatch{author: rec.Author, extracted: ex}
	}
	return got
}

// rawServer writes the response for each request's URI exactly as given
// and closes the connection. With a certificate it speaks TLS; a plaintext
// server drops TLS handshakes at once. With a banner it sends the banner
// first and answers nothing.
func rawServer(t *testing.T, pages map[string]string, cert *tls.Certificate, banner string) int {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := ln.Addr().(*net.TCPAddr).Port
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				c.SetDeadline(time.Now().Add(5 * time.Second))
				if banner != "" {
					c.Write([]byte(banner))
					bufio.NewReader(c).WriteTo(io.Discard)
					return
				}
				br := bufio.NewReader(c)
				first, err := br.Peek(1)
				if err != nil {
					return
				}
				conn := net.Conn(c)
				if first[0] == 0x16 { // TLS handshake
					if cert == nil {
						return
					}
					conn = tls.Server(&peekConn{c, br}, &tls.Config{Certificates: []tls.Certificate{*cert}})
					br = bufio.NewReader(conn)
				} else if cert != nil {
					return
				}
				line, err := br.ReadString('\n')
				if err != nil {
					return
				}
				fields := strings.Fields(line)
				for {
					l, err := br.ReadString('\n')
					if err != nil || strings.TrimRight(l, "\r\n") == "" {
						break
					}
				}
				resp, ok := "", false
				if len(fields) > 1 {
					resp, ok = pages[fields[1]]
				}
				if !ok {
					resp = "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n"
				}
				conn.Write([]byte(resp))
				if tc, ok := conn.(*tls.Conn); ok {
					tc.CloseWrite()
				}
			}(c)
		}
	}()
	return port
}

// peekConn reads through the bufio.Reader that peeked at the first byte.
type peekConn struct {
	net.Conn
	r *bufio.Reader
}

func (c *peekConn) Read(p []byte) (int, error) { return c.r.Read(p) }

func httpResponse(head, body string) string {
	return head + "Content-Length: " + strconv.Itoa(len(body)) + "\r\n\r\n" + body
}

func gzipped(s string) string {
	var b bytes.Buffer
	w := gzip.NewWriter(&b)
	w.Write([]byte(s))
	w.Close()
	return b.String()
}

// diffServers starts servers whose responses exercise how athar scan reads
// HTTP, HTML, favicons, certificates and banners.
func diffServers(t *testing.T) map[string]int {
	t.Helper()
	page := "<HTML><head><TITLE lang=en>\n  Acme&nbsp;&mdash;\tConsole &#x41;&#66;&amp;&ampx&notit; &#128;&#0;&#xD800;&lang; &unknown; \u2003end </TITLE>" +
		"<link rel=stylesheet href=/x.css><LINK data-rel=x REL='Shortcut ICON' href=\"./static/../img/fav%20icon.png?v=1#frag\">" +
		"</head><body>Hello MixedCase \u212Aelvin</body></HTML>"
	gz := gzipped("<title>\u212Aelvin \u017Ftrix</title><link rel=icon href=\"data:image/png;base64,SUNP\nTg==\">")
	chunked := fmt.Sprintf("%x;ext=1\r\n%s\r\n%x\r\n%s\r\n0\r\nX-Trailer: v\r\n\r\n", 10, gz[:10], len(gz)-10, gz[10:])

	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	ca := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "Acme CA", Organization: []string{"Acme Trust"}},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign,
	}
	leaf := &x509.Certificate{
		SerialNumber: new(big.Int).SetBytes([]byte{0xff, 0x01, 0x00}),
		Subject:      pkix.Name{CommonName: "Acme Panel", Organization: []string{"Acme", "Acme Two"}},
		NotBefore:    time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		DNSNames:    []string{"panel.acme.example", "*.acme.example"},
		IPAddresses: []net.IP{net.ParseIP("192.0.2.10"), net.ParseIP("2001:db8::1"), net.ParseIP("2001:db8:0:1:0:0:0:1")},
	}
	der, err := x509.CreateCertificate(rand.Reader, leaf, ca, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert := &tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}

	// gzip bodies: athar scan keeps what decodes once the header is valid.
	var lines strings.Builder
	for i := range 300 {
		fmt.Fprintf(&lines, "<p>line %d %x</p>\n", i, i*7919)
	}
	cut := gzipped("<title>cut</title>" + lines.String())
	cut = cut[:len(cut)/2]
	var named bytes.Buffer
	nw := gzip.NewWriter(&named)
	nw.Header = gzip.Header{Name: "page.html", Comment: "athar test", Extra: []byte("xx")}
	nw.Write([]byte("<title>named</title>"))
	nw.Close()
	hcrc := []byte{0x1f, 0x8b, 8, 2, 0, 0, 0, 0, 0, 0xff}
	hcrc = binary.LittleEndian.AppendUint16(hcrc, uint16(crc32.ChecksumIEEE(hcrc)))
	var deflated bytes.Buffer
	fw, _ := flate.NewWriter(&deflated, flate.DefaultCompression)
	fw.Write([]byte("<title>hcrc</title>"))
	fw.Close()
	hcrc = append(hcrc, deflated.Bytes()...)
	hcrc = binary.LittleEndian.AppendUint32(hcrc, crc32.ChecksumIEEE([]byte("<title>hcrc</title>")))
	hcrc = binary.LittleEndian.AppendUint32(hcrc, uint32(len("<title>hcrc</title>")))
	gzipPage := func(body string) map[string]string {
		return map[string]string{"/": httpResponse("HTTP/1.1 200 OK\r\nContent-Encoding: gzip\r\n", body)}
	}

	return map[string]int{
		"entities and headers": rawServer(t, map[string]string{
			"/": httpResponse("HTTP/1.1 200 OK\r\nServer:  Acme   Web/1.2 \r\nX-Multi: a\r\nx-multi: b\r\nX-Fold: first\r\n   second\r\n"+
				"Connection: close\r\nContent-Type: text/html\r\n", page),
			"/img/fav%20icon.png?v=1": httpResponse("HTTP/1.1 200 OK\r\n", "ICON"),
		}, nil, ""),
		"chunked gzip": rawServer(t, map[string]string{
			"/": "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nContent-Encoding: gzip\r\nContent-Length: 5\r\nTrailer: X-Trailer\r\n\r\n" + chunked,
		}, nil, ""),
		"HTTP/1.0 until close": rawServer(t, map[string]string{
			"/": "HTTP/1.0 200 OK\r\nConnection: close\r\nX-Powered-By: PHP\r\n\r\n<title>Old  site</title><link rel=icon href=//otherhost/x.ico>",
		}, nil, ""),
		"bare LF": rawServer(t, map[string]string{
			"/": "HTTP/1.1 404 Not Found\nServer: lf\nContent-Length: 3\n\nabc",
		}, nil, ""),
		"no body": rawServer(t, map[string]string{
			"/": "HTTP/1.1 304 Not Modified\r\nContent-Length: 10\r\nTransfer-Encoding: chunked\r\n\r\n",
		}, nil, ""),
		"rejected header": rawServer(t, map[string]string{
			"/": "HTTP/1.1 200 OK\r\nX-Bad\x01: x\r\nContent-Length: 17\r\n\r\n<title>no</title>",
		}, nil, ""),
		"escaped favicon path": rawServer(t, map[string]string{
			"/":              httpResponse("HTTP/1.1 200 OK\r\n", `<title>esc</title><link href="img/a b.png" rel="ICON">`),
			"/img/a%20b.png": httpResponse("HTTP/1.1 200 OK\r\n", "SPACE"),
		}, nil, ""),
		"favicon link without a path": rawServer(t, map[string]string{
			"/":            httpResponse("HTTP/1.1 200 OK\r\n", `<title>self</title><link rel=icon href="?v=2#x">`),
			"/?v=2":        httpResponse("HTTP/1.1 200 OK\r\n", `<title>self</title><link rel=icon href="?v=2#x">`),
			"/favicon.ico": httpResponse("HTTP/1.1 200 OK\r\n", "ICO3"),
		}, nil, ""),
		"favicon link without a hierarchy": rawServer(t, map[string]string{
			"/":            httpResponse("HTTP/1.1 200 OK\r\n", `<title>void</title><link rel=icon href="javascript:void(0)?v=3">`),
			"/?v=3":        httpResponse("HTTP/1.1 200 OK\r\n", `<title>void</title>`),
			"/favicon.ico": httpResponse("HTTP/1.1 200 OK\r\n", "ICO4"),
		}, nil, ""),
		"headers as received": rawServer(t, map[string]string{
			"/": "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nConnection: Keep-Alive, close\r\nContent-Length: 7\r\ncontent-length: 7\r\n" +
				"Trailer: X-Sum\r\nPragma: no-cache\r\n\r\n12\r\n<title>hdr</title>\r\n0\r\nX-Sum: 1\r\n\r\n",
		}, nil, ""),
		"custom probe": rawServer(t, map[string]string{
			"/":           httpResponse("HTTP/1.1 200 OK\r\n", "<title>api</title>"),
			"/api/health": "HTTP/1.1 204 No Content\r\nX-Health: ok\r\n\r\n",
		}, nil, ""),
		"TLS": rawServer(t, map[string]string{
			"/":            httpResponse("HTTP/1.1 200 OK\r\n", "<title>TLS</title>"),
			"/favicon.ico": httpResponse("HTTP/1.1 200 OK\r\n", "ICO2"),
		}, cert, ""),
		"banner":             rawServer(t, nil, nil, "SSH-2.0-OpenSSH_9.6 Ubuntu\r\n"),
		"gzip corrupt":       rawServer(t, gzipPage("\x1f\x8b\x08\x00\x00\x00\x00\x00\x00\xff\xff\xfe not deflate"), nil, ""),
		"gzip truncated":     rawServer(t, gzipPage(cut), nil, ""),
		"gzip header fields": rawServer(t, gzipPage(named.String()), nil, ""),
		"gzip header CRC":    rawServer(t, gzipPage(string(hcrc)), nil, ""),
	}
}

// diffRules read every field through extract and check operators. With
// banner, an SSH rule makes both scanners wait for banners.
func diffRules(t *testing.T, banner bool) []*rule.Rule {
	t.Helper()
	src := []string{`
title: diff fields
id: 10000000-0000-4000-8000-000000000001
target: {protocol: http}
detection:
  selection:
    service.port|exists: true
  condition: selection
extract:
  title: {field: http.title, regex: '(?s)^(.*)$'}
  status: {field: http.status_code, regex: '^(.*)$'}
  server: {field: http.headers.server, regex: '(?s)^(.*)$'}
  multi: {field: http.headers.x-multi, regex: '(?s)^(.*)$'}
  fold: {field: http.headers.x-fold, regex: '(?s)^(.*)$'}
  raw: {field: http.headers_raw, regex: '(?s)^(.*)$'}
  body: {field: http.body, regex: '(?s)^(.*)$'}
  body_mmh3: {field: http.body.mmh3, regex: '^(.*)$'}
  body_sha256: {field: http.body.sha256, regex: '^(.*)$'}
  icon_mmh3: {field: http.favicon.mmh3, regex: '^(.*)$'}
  icon_md5: {field: http.favicon.md5, regex: '^(.*)$'}
  icon_sha256: {field: http.favicon.sha256, regex: '^(.*)$'}
  protocol: {field: service.protocol, regex: '^(.*)$'}
  cl: {field: http.headers.content-length, regex: '^(.*)$'}
  te: {field: http.headers.transfer-encoding, regex: '^(.*)$'}
  conn: {field: http.headers.connection, regex: '^(.*)$'}
  trailer: {field: http.headers.trailer, regex: '^(.*)$'}
  powered: {field: http.headers.x-powered-by, regex: '^(.*)$'}
  health: {field: http.headers.x-health, regex: '^(.*)$'}
  pragma: {field: http.headers.pragma, regex: '^(.*)$'}
  cache: {field: http.headers.cache-control, regex: '^(.*)$'}
  cn: {field: tls.cert.subject.cn, regex: '^(.*)$'}
  org: {field: tls.cert.subject.o, regex: '^(.*)$'}
  issuer_cn: {field: tls.cert.issuer.cn, regex: '^(.*)$'}
  issuer_o: {field: tls.cert.issuer.o, regex: '^(.*)$'}
  serial: {field: tls.cert.serial, regex: '^(.*)$'}
  cert_sha256: {field: tls.cert.sha256, regex: '^(.*)$'}
  cert_sha1: {field: tls.cert.sha1, regex: '^(.*)$'}
  san: {field: tls.cert.san, regex: '^(.*)$'}
  brand: {field: http.title, regex: '^(?P<brand>\w+)\s*(?:&|—)'}
`, `
title: diff lists
id: 10000000-0000-4000-8000-000000000002
target: {protocol: http}
detection:
  selection_multi:
    http.headers.x-multi|all: [a, b]
  selection_cert:
    tls.cert.subject.o|all: ['Acme', 'acme two']
    tls.cert.san|all: ['PANEL.acme.example', '\*.acme.example', '192.0.2.10', '2001:db8::1', '2001:db8:0:1::1']
  condition: 1 of selection_*
`, `
title: diff fold
id: 10000000-0000-4000-8000-000000000003
target: {protocol: http}
detection:
  selection:
    http.title|contains: 'kelvin strix'
  condition: selection
`, `
title: diff cased
id: 10000000-0000-4000-8000-000000000004
target: {protocol: http}
detection:
  selection:
    http.title|contains|cased: 'kelvin'
  condition: selection
`, `
title: diff wildcard and regex
id: 10000000-0000-4000-8000-000000000005
target: {protocol: http}
detection:
  selection_wild:
    http.title: 'acme*console*end'
  selection_re:
    http.body|re: 'Hello (?i:mixedcase) \x{212A}elvin'
  condition: selection_wild and selection_re
`, `
title: diff keyword and numbers
id: 10000000-0000-4000-8000-000000000006
target: {protocol: http}
detection:
  keywords:
    - 'web/1.2'
    - 'x-trailer'
  selection_status:
    http.status_code|gte: 400
  condition: keywords or selection_status
`, `
title: diff absent title
id: 10000000-0000-4000-8000-000000000007
target: {protocol: http}
detection:
  selection:
    http.title|exists: false
  filter:
    http.status_code: 404
  condition: selection and not filter
`, `
title: diff custom probe
id: 10000000-0000-4000-8000-000000000008
target: {protocol: http}
probes:
  health:
    protocol: http
    request: {method: HEAD, path: /api/health}
detection:
  selection:
    probe: health
    http.status_code: 204
    http.headers.x-health: 'OK'
  condition: selection
`, `
title: diff TLS required
id: 10000000-0000-4000-8000-000000000009
target: {protocol: http, tls: required}
detection:
  selection:
    http.title|endswith: 'tls'
  condition: selection
`, `
title: diff TLS none
id: 10000000-0000-4000-8000-00000000000a
target: {protocol: http, tls: none}
detection:
  selection:
    http.status_code|exists: true
  condition: selection
`, `
title: diff headers as received
id: 10000000-0000-4000-8000-00000000000c
target: {protocol: http}
detection:
  selection:
    http.headers.transfer-encoding: 'chunked'
    http.headers.connection: 'keep-alive, close'
    http.headers.content-length|all: ['7']
    http.headers.trailer: 'x-sum'
    http.headers.pragma: 'no-cache'
  filter:
    http.headers.cache-control|exists: true
  condition: selection and not filter
`}
	if banner {
		src = append(src, `
title: diff banner
id: 10000000-0000-4000-8000-00000000000b
target: {protocol: ssh}
detection:
  selection:
    service.banner|hex|startswith: '5353482d'
  condition: selection
extract:
  banner: {field: service.banner, regex: '(?s)^(.*)$'}
  ssh: {field: ssh.banner, regex: '^(.*)$'}
  protocol: {field: service.protocol, regex: '^(.*)$'}
`)
	}
	var rules []*rule.Rule
	for i, s := range src {
		r := parse(t, fmt.Sprintf("diff_%d.yml", i), s)
		if _, _, err := eval.Compile(r); err != nil {
			t.Fatalf("%s: %v", r.Title, err)
		}
		rules = append(rules, r)
	}
	return rules
}
