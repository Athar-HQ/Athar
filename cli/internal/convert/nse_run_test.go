package convert

import (
	"bufio"
	"bytes"
	"compress/flate"
	"compress/gzip"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/md5"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"encoding/hex"
	"encoding/xml"
	"fmt"
	"hash/crc32"
	"io"
	"math/big"
	"net"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"regexp"
	"slices"
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
		"early hints", "cut short", "chunked without end", "chunked without last CRLF", "chunked with trailer",
		"chunked bad trailer", "gzip bad CRC", "gzip and more", "gzip members", "gzip bad checksum"}
	expect := map[string][]string{
		"diff lists":               {"entities and headers", "TLS", "TLS until close"},
		"diff fold":                {"chunked gzip"},
		"diff wildcard and regex":  {"entities and headers"},
		"diff keyword and numbers": {"entities and headers", "chunked gzip", "bare LF"},
		"diff absent title":        {"no body", "rejected header", "banner", "gzip corrupt"},
		"diff custom probe":        {"custom probe"},
		"diff TLS required":        {"TLS", "TLS until close"},
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

// truncatedAlike accepts the one difference between Go's flate and zlib:
// at the end of a truncated stream, zlib can emit a few more bytes, because
// Go reads ahead before it decodes the last symbols. Neither hashes it.
func truncatedAlike(field, a, b string) bool {
	return field == "body" && strings.HasPrefix(b, a) && len(b)-len(a) <= 8
}

// TestNSEHashesWholeBodies compares athar scan and athar.nse on bodies and
// icons longer than http.body keeps. Both hash them whole up to the same
// limit, and neither hashes one that is longer or cut short.
func TestNSEHashesWholeBodies(t *testing.T) {
	bin := nmapBin(t)
	var lines strings.Builder
	for i := 0; lines.Len() < 3<<20; i++ {
		fmt.Fprintf(&lines, "<p>line %d %x</p>\n", i, i*7919)
	}
	big := `<link rel="icon" href="/large.ico">` + lines.String()
	icon := strings.Repeat("\x00\x01icon", 400_000)
	limit := strings.Repeat("a", 16<<20) // the scanner's maxHashBody
	ok := func(body string) string { return httpResponse("HTTP/1.1 200 OK\r\n", body) }
	cut := func(body string) string { return ok(body)[:len(ok(body))-1] }
	chunked := func(body string) string {
		var b strings.Builder
		b.WriteString("HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n")
		for ; len(body) > 0; body = body[min(len(body), 1<<20):] {
			piece := body[:min(len(body), 1<<20)]
			fmt.Fprintf(&b, "%x\r\n%s\r\n", len(piece), piece)
		}
		b.WriteString("0\r\n\r\n")
		return b.String()
	}
	servers := map[string]int{
		"large":          rawServer(t, map[string]string{"/": ok(big), "/large.ico": ok(icon), "/large.css": chunked(big)}, nil, ""),
		"large gzip":     rawServer(t, map[string]string{"/": httpResponse("HTTP/1.1 200 OK\r\nContent-Encoding: gzip\r\n", gzipped(big)), "/large.ico": cut(icon)}, nil, ""),
		"at the limit":   rawServer(t, map[string]string{"/": chunked(limit)}, nil, ""),
		"over the limit": rawServer(t, map[string]string{"/": chunked(limit + "a")}, nil, ""),
		"cut short":      rawServer(t, map[string]string{"/": cut(big), "/large.css": cut(big)}, nil, ""),
	}
	expect := map[string][]string{
		"whole body":     {"large", "large gzip", "at the limit"},
		"no body hashes": {"over the limit", "cut short"},
		"whole icon":     {"large"},
		"no icon hashes": {"large gzip", "at the limit", "over the limit", "cut short"},
		"whole file":     {"large"},
	}
	sum := func(s string) string { h := sha256.Sum256([]byte(s)); return hex.EncodeToString(h[:]) }
	md := md5.Sum([]byte(icon))
	var rules []*rule.Rule
	for i, src := range []string{fmt.Sprintf(`
title: whole body
detection:
  selection:
    http.body.sha256: [%s, %s]
    http.body.mmh3: [%d, %d]
  condition: selection
`, sum(big), sum(limit), probe.MMH3([]byte(big)), probe.MMH3([]byte(limit))), `
title: no body hashes
detection:
  selection:
    http.status_code: 200
    http.body.sha256|exists: false
    http.body.mmh3|exists: false
  condition: selection
`, fmt.Sprintf(`
title: whole icon
detection:
  selection:
    http.favicon.sha256: %s
    http.favicon.md5: %s
    http.favicon.mmh3: %d
  condition: selection
`, sum(icon), hex.EncodeToString(md[:]), probe.FaviconMMH3([]byte(icon))), `
title: no icon hashes
detection:
  selection:
    http.status_code: 200
    http.favicon.sha256|exists: false
    http.favicon.md5|exists: false
    http.favicon.mmh3|exists: false
  condition: selection
`, fmt.Sprintf(`
title: whole file
probes:
  css:
    protocol: http
    request: {path: /large.css}
detection:
  selection:
    probe: css
    http.body.sha256: %s
  condition: selection
`, sum(big))} {
		rules = append(rules, parse(t, fmt.Sprintf("whole_%d.yml", i),
			fmt.Sprintf("id: 10000000-0000-4000-8000-0000000001%02d\ntarget: {protocol: http}%s", i, src)))
	}
	var ports []int
	for _, p := range servers {
		ports = append(ports, p)
	}
	want := scanRecords(t, rules, ports)
	got := runNSE(t, bin, rules, ports, "athar.probes", "athar.timeout=10s")
	for name, port := range servers {
		for _, r := range rules {
			_, wok := want[port][r.ID]
			_, gok := got[port][r.ID]
			if expected := slices.Contains(expect[r.Title], name); wok != expected || gok != expected {
				t.Errorf("%s, %s: athar scan matched=%v, athar.nse matched=%v, want %v", name, r.Title, wok, gok, expected)
			}
		}
	}
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

func nmapBin(t *testing.T) string {
	t.Helper()
	bin, err := exec.LookPath("nmap")
	if err != nil {
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
	// Several gzip members: athar scan reads them all, up to a member whose
	// checksum is wrong. The long member compresses badly.
	var long strings.Builder
	for i := range 600 {
		fmt.Fprintf(&long, "<p>%x</p>\n", sha256.Sum256([]byte{byte(i), byte(i >> 8)}))
	}
	members := gzipped("<title>members</title>") + gzipped("") + gzipped(long.String()) + gzipped("<p>last member</p>")
	badSum := []byte(gzipped("<title>checksum</title>"))
	badSum[len(badSum)-8] ^= 0xff
	// Bodies that don't come to their end have no hashes; one that does has.
	badCRC := []byte(gzipped("<title>bad crc</title>"))
	badCRC[len(badCRC)-8] ^= 0xff
	chunkedPage := func(end string) map[string]string {
		return map[string]string{"/": "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n14\r\n<title>chunk</title>\r\n" + end}
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
		"gzip members":       rawServer(t, gzipPage(members), nil, ""),
		"gzip bad checksum":  rawServer(t, gzipPage(string(badSum)+gzipped("<p>not read</p>")), nil, ""),
		"early hints": rawServer(t, map[string]string{
			"/": "HTTP/1.1 100 Continue\r\n\r\nHTTP/1.1 103 Early Hints\r\nLink: </x.css>; rel=preload\r\nServer: early\r\n\r\n" +
				httpResponse("HTTP/1.1 200 OK\r\nServer: final\r\n", "<title>hinted</title>"),
		}, nil, ""),
		"cut short": rawServer(t, map[string]string{
			"/": "HTTP/1.1 200 OK\r\nContent-Length: 100\r\n\r\n<title>short</title>",
		}, nil, ""),
		"TLS until close": rawServer(t, map[string]string{
			"/":            "HTTP/1.0 200 OK\r\n\r\n<title>old TLS</title>",
			"/favicon.ico": "HTTP/1.0 200 OK\r\n\r\nICO3",
		}, cert, ""),
		"chunked without end":       rawServer(t, chunkedPage(""), nil, ""),
		"chunked without last CRLF": rawServer(t, chunkedPage("0\r\n"), nil, ""),
		"chunked with trailer":      rawServer(t, chunkedPage("0\r\nX-Sum: 1\r\n folded\r\n\r\n"), nil, ""),
		"chunked bad trailer":       rawServer(t, chunkedPage("0\r\nno colon\r\n\r\n"), nil, ""),
		"gzip bad CRC":              rawServer(t, gzipPage(string(badCRC)), nil, ""),
		"gzip and more":             rawServer(t, gzipPage(gzipped("<title>more</title>")+"junk after the end"), nil, ""),
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
