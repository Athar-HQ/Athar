package probe

import (
	"bufio"
	"bytes"
	"context"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Athar-HQ/Athar/cli/internal/rule"
)

// Vectors computed with Python's mmh3 package.
func TestMMH3(t *testing.T) {
	all := make([]byte, 256)
	for i := range all {
		all[i] = byte(i)
	}
	for _, tt := range []struct {
		in   []byte
		want int32
	}{
		{nil, 0},
		{[]byte("a"), 1009084850},
		{[]byte("ab"), -1681926305},
		{[]byte("abc"), -1277324294},
		{[]byte("abcd"), 1139631978},
		{[]byte("hello world"), 1586663183},
		{all, -469103018},
	} {
		if got := MMH3(tt.in); got != tt.want {
			t.Errorf("MMH3(%q) = %d, want %d", tt.in, got, tt.want)
		}
	}

	icon := bytes.Repeat(all, 3) // base64 spans several 76-character lines
	if got := FaviconMMH3(icon); got != 1836528006 {
		t.Errorf("FaviconMMH3(3x256 bytes) = %d, want 1836528006", got)
	}
	if got := FaviconMMH3(all[:57]); got != 459585070 { // exactly one full line
		t.Errorf("FaviconMMH3(57 bytes) = %d, want 459585070", got)
	}
}

func TestParsePorts(t *testing.T) {
	got, err := ParsePorts("443, 80,8000-8002,80")
	if err != nil {
		t.Fatal(err)
	}
	if want := []int{443, 80, 8000, 8001, 8002}; !reflect.DeepEqual(got, want) {
		t.Errorf("got %v, want %v", got, want)
	}
	for _, bad := range []string{"", "0", "65536", "80-79", "http", "1-", ","} {
		if _, err := ParsePorts(bad); err == nil {
			t.Errorf("ParsePorts(%q): want error", bad)
		}
	}
}

func TestParseTarget(t *testing.T) {
	for _, tt := range []struct {
		in   string
		want string // Host|Prefix|Port
	}{
		{"10.0.0.1", "10.0.0.1||0"},
		{"10.0.0.0/30", "|10.0.0.0/30|0"},
		{"10.0.0.7/30", "|10.0.0.4/30|0"},
		{"10.0.0.1:8443", "10.0.0.1||8443"},
		{"2001:db8::1", "2001:db8::1||0"},
		{"[2001:db8::1]:443", "2001:db8::1||443"},
		{"example.org", "example.org||0"},
		{"example.org.", "example.org||0"},
		{"example.org:8080", "example.org||8080"},
	} {
		tg, err := ParseTarget(tt.in)
		if err != nil {
			t.Errorf("%s: %v", tt.in, err)
			continue
		}
		prefix := ""
		if tg.Prefix.IsValid() {
			prefix = tg.Prefix.String()
		}
		if got := tg.Host + "|" + prefix + "|" + strconv.Itoa(tg.Port); got != tt.want {
			t.Errorf("%s: got %s, want %s", tt.in, got, tt.want)
		}
	}
	for _, bad := range []string{"", "http://example.org", "10.0.0.0/8", "10.0.0.0/33", "host:0", "host:http", "a b"} {
		if _, err := ParseTarget(bad); err == nil {
			t.Errorf("ParseTarget(%q): want error", bad)
		}
	}
}

func TestEachAndCount(t *testing.T) {
	var targets []Target
	for _, s := range []string{"10.0.0.0/31", "h.example", "10.9.9.9:2222"} {
		tg, err := ParseTarget(s)
		if err != nil {
			t.Fatal(err)
		}
		targets = append(targets, tg)
	}
	ports := []int{80, 443}
	var got []string
	Each(targets, ports, func(h string, p int) bool {
		got = append(got, net.JoinHostPort(h, strconv.Itoa(p)))
		return true
	})
	want := []string{
		"10.0.0.0:80", "10.0.0.1:80", "h.example:80",
		"10.0.0.0:443", "10.0.0.1:443", "h.example:443",
		"10.9.9.9:2222",
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("Each order:\n got %v\nwant %v", got, want)
	}
	if hosts, checks := Count(targets, ports); hosts != 4 || checks != 7 {
		t.Errorf("Count = %d hosts, %d checks; want 4, 7", hosts, checks)
	}
}

// Within a port, Each visits every host once in a spread order, so
// consecutive checks go to different /24s of a /16.
func TestEachSpread(t *testing.T) {
	big, err := ParseTarget("10.0.0.0/16")
	if err != nil {
		t.Fatal(err)
	}
	seen := map[string]bool{}
	nets := map[netip.Prefix]bool{}
	Each([]Target{big}, []int{80}, func(h string, p int) bool {
		a := netip.MustParseAddr(h)
		if !big.Prefix.Contains(a) || seen[h] {
			t.Fatalf("host %s is outside the range or repeated", h)
		}
		seen[h] = true
		if len(seen) <= 256 {
			nets[netip.PrefixFrom(a, 24).Masked()] = true
		}
		return true
	})
	if len(seen) != 1<<16 {
		t.Errorf("visited %d hosts, want %d", len(seen), 1<<16)
	}
	if len(nets) < 200 {
		t.Errorf("the first 256 checks went to %d /24s, want at least 200", len(nets))
	}

	// Ranges, IPv6 and names mixed: each host once per port, port by port,
	// host:port targets last.
	var targets []Target
	for _, s := range []string{"192.0.2.0/29", "a.example", "2001:db8::/126", "b.example", "10.9.9.9:2222"} {
		tg, err := ParseTarget(s)
		if err != nil {
			t.Fatal(err)
		}
		targets = append(targets, tg)
	}
	want := []string{"a.example", "b.example", "2001:db8::", "2001:db8::1", "2001:db8::2", "2001:db8::3"}
	for i := range 8 {
		want = append(want, "192.0.2."+strconv.Itoa(i))
	}
	sort.Strings(want)
	var got []string
	Each(targets, []int{1, 2}, func(h string, p int) bool {
		got = append(got, net.JoinHostPort(h, strconv.Itoa(p)))
		return true
	})
	if len(got) != 2*len(want)+1 || got[len(got)-1] != "10.9.9.9:2222" {
		t.Fatalf("Each visited %v", got)
	}
	for i, port := range []string{"1", "2"} {
		var hosts []string
		for _, hp := range got[i*len(want) : (i+1)*len(want)] {
			h, p, _ := net.SplitHostPort(hp)
			if p != port {
				t.Fatalf("port %s check %s out of order: %v", port, hp, got)
			}
			hosts = append(hosts, h)
		}
		sort.Strings(hosts)
		if !reflect.DeepEqual(hosts, want) {
			t.Errorf("port %s hosts:\n got %v\nwant %v", port, hosts, want)
		}
	}

	calls := 0
	Each(targets, []int{1, 2}, func(string, int) bool { calls++; return calls < 5 })
	if calls != 5 {
		t.Errorf("Each made %d calls after fn returned false, want 5", calls)
	}
}

func TestDefaultPorts(t *testing.T) {
	seen := map[int]bool{}
	for _, p := range DefaultPorts {
		if p < 1 || p > 65535 || seen[p] {
			t.Errorf("DefaultPorts: port %d is invalid or repeated", p)
		}
		seen[p] = true
	}
}

func TestTitleAndFavicon(t *testing.T) {
	if got, _ := title([]byte("<html><TITLE lang=en>\n  NKW &mdash;  Console\n</TITLE>")); got != "NKW — Console" {
		t.Errorf("title = %q", got)
	}
	if _, ok := title([]byte("<html>no title</html>")); ok {
		t.Error("title found where there is none")
	}

	body := []byte(`<link rel="stylesheet" href="/a.css"><link rel="apple-touch-icon" href="/apple.png"><LINK REL='shortcut icon' HREF='img/fav.ico?v=2'>`)
	if got := faviconRef(body); got != "img/fav.ico?v=2" {
		t.Errorf("faviconRef = %q", got)
	}
	for _, tt := range []struct {
		ref, path string
		inline    string
	}{
		{"", "/favicon.ico", ""},
		{"img/fav.ico?v=2", "/img/fav.ico?v=2", ""},
		{"/static/icon.png", "/static/icon.png", ""},
		{"http://10.0.0.1:8080/x.ico", "/x.ico", ""},
		{"//cdn.example/x.ico", "/favicon.ico", ""},
		{"https://cdn.example/x.ico", "/favicon.ico", ""},
		{"data:image/png;base64,aGVsbG8=", "", "hello"},
		{"data:,hi%20there", "", "hi there"},
	} {
		path, inline := faviconSource(tt.ref, "10.0.0.1", 8080)
		if path != tt.path || string(inline) != tt.inline {
			t.Errorf("faviconSource(%q) = %q, %q; want %q, %q", tt.ref, path, inline, tt.path, tt.inline)
		}
	}
}

func testProber(needs Needs) *Prober {
	return &Prober{Timeout: 2 * time.Second, BannerWait: 300 * time.Millisecond, UserAgent: "athar-test", Needs: needs}
}

func hostPort(t *testing.T, rawURL string) (string, int) {
	t.Helper()
	u, err := url.Parse(rawURL)
	if err != nil {
		t.Fatal(err)
	}
	port, _ := strconv.Atoi(u.Port())
	return u.Hostname(), port
}

var icon = []byte("\x89PNG fake icon bytes")

func panelHandler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Server", "nginx")
		w.Header().Add("X-Multi", "a")
		w.Header().Add("X-Multi", "b")
		w.Write([]byte(`<html><head><title>NKW — Autonomous Penetration Testing Console</title>
<link rel="icon" href="/static/icon.png"></head><body><a href="/function/tasks">tasks</a></body></html>`))
	})
	mux.HandleFunc("/static/icon.png", func(w http.ResponseWriter, r *http.Request) { w.Write(icon) })
	mux.HandleFunc("/api/version", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"product":"ExamplePanel","version":"1.2"}`))
	})
	return mux
}

func TestProbeHTTP(t *testing.T) {
	srv := httptest.NewServer(panelHandler())
	defer srv.Close()
	host, port := hostPort(t, srv.URL)

	p := testProber(Needs{TLS: true, HTTP: true, Favicon: true})
	svc := p.Probe(context.Background(), host, port)
	if svc == nil {
		t.Fatal("port reported closed")
	}
	f := svc.Fields
	if svc.TLS {
		t.Error("plaintext server reported as TLS")
	}
	checks := map[string]any{
		"service.port":         port,
		"service.protocol":     "http",
		"http.status_code":     200,
		"http.title":           "NKW — Autonomous Penetration Testing Console",
		"http.headers.server":  "nginx",
		"http.headers.x-multi": []any{"a", "b"},
		"http.favicon.mmh3":    int(FaviconMMH3(icon)),
		"http.favicon.md5":     md5Hex(icon),
	}
	for k, want := range checks {
		if !reflect.DeepEqual(f[k], want) {
			t.Errorf("%s = %#v, want %#v", k, f[k], want)
		}
	}
	if body, _ := f["http.body"].(string); !strings.Contains(body, "/function/tasks") {
		t.Errorf("http.body = %q", body)
	}
	if raw, _ := f["http.headers_raw"].(string); !strings.HasPrefix(raw, "HTTP/1.1 200 OK\r\n") || !strings.Contains(raw, "Server: nginx\r\n") {
		t.Errorf("http.headers_raw = %q", raw)
	}
	if _, ok := f["service.banner"]; ok {
		t.Error("banner set although no banner was needed")
	}
}

func TestProbeTLS(t *testing.T) {
	srv := httptest.NewTLSServer(panelHandler())
	defer srv.Close()
	host, port := hostPort(t, srv.URL)

	svc := testProber(Needs{TLS: true, HTTP: true}).Probe(context.Background(), host, port)
	if svc == nil || !svc.TLS {
		t.Fatalf("expected a TLS service, got %+v", svc)
	}
	f := svc.Fields
	if f["tls.cert.subject.o"] != "Acme Co" {
		t.Errorf("tls.cert.subject.o = %#v", f["tls.cert.subject.o"])
	}
	if san, _ := f["tls.cert.san"].([]any); len(san) == 0 || san[0] != "example.com" {
		t.Errorf("tls.cert.san = %#v", f["tls.cert.san"])
	}
	for _, k := range []string{"tls.version", "tls.cipher", "tls.cert.sha256", "tls.cert.sha1", "tls.cert.serial", "tls.cert.self_signed"} {
		if _, ok := f[k]; !ok {
			t.Errorf("%s missing", k)
		}
	}
	if f["http.title"] != "NKW — Autonomous Penetration Testing Console" {
		t.Errorf("http.title over TLS = %#v", f["http.title"])
	}
	if _, ok := f["http.favicon.mmh3"]; ok {
		t.Error("favicon fetched although not needed")
	}
}

// listen starts a TCP server that runs handle for every connection.
func listen(t *testing.T, handle func(net.Conn)) (string, int) {
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
			go func() { defer c.Close(); handle(c) }()
		}
	}()
	addr := ln.Addr().(*net.TCPAddr)
	return "127.0.0.1", addr.Port
}

func TestProbeBanner(t *testing.T) {
	host, port := listen(t, func(c net.Conn) {
		c.Write([]byte("SSH-2.0-OpenSSH_9.6\r\n"))
		time.Sleep(500 * time.Millisecond)
	})
	svc := testProber(Needs{Banner: true, TLS: true, HTTP: true}).Probe(context.Background(), host, port)
	if svc == nil {
		t.Fatal("port reported closed")
	}
	if svc.Fields["ssh.banner"] != "SSH-2.0-OpenSSH_9.6" || svc.Fields["service.protocol"] != "ssh" {
		t.Errorf("fields = %#v", svc.Fields)
	}
	if svc.TLS {
		t.Error("banner service reported as TLS")
	}
	if _, ok := svc.Fields["http.status_code"]; ok {
		t.Error("HTTP sent to a banner service")
	}
}

func TestProbeHTTPWithBannerWait(t *testing.T) {
	// A banner rule is loaded, so the prober waits for a banner, gets none,
	// fails TLS on the same connection and falls back to plaintext HTTP.
	srv := httptest.NewServer(panelHandler())
	defer srv.Close()
	host, port := hostPort(t, srv.URL)
	svc := testProber(Needs{Banner: true, TLS: true, HTTP: true}).Probe(context.Background(), host, port)
	if svc == nil || svc.Fields["http.status_code"] != 200 {
		t.Fatalf("got %+v", svc)
	}
}

func TestProbeClosed(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := ln.Addr().(*net.TCPAddr).Port
	ln.Close()
	if svc := testProber(Needs{TLS: true, HTTP: true}).Probe(context.Background(), "127.0.0.1", port); svc != nil {
		t.Errorf("closed port reported open: %+v", svc)
	}
}

func TestCustomProbes(t *testing.T) {
	srv := httptest.NewServer(panelHandler())
	defer srv.Close()
	host, port := hostPort(t, srv.URL)

	api := rule.Probe{Protocol: "http", Request: &rule.HTTPRequest{Method: "GET", Path: "/api/version"}}
	post := rule.Probe{Protocol: "http", Request: &rule.HTTPRequest{Method: "POST", Path: "/api/version"}}
	p := testProber(Needs{HTTP: true})
	p.Custom = []CustomProbe{{Key: ProbeKey(api), Probe: api}, {Key: ProbeKey(post), Probe: post}}
	svc := p.Probe(context.Background(), host, port)
	if svc == nil {
		t.Fatal("port reported closed")
	}
	if body, _ := svc.Custom[ProbeKey(api)]["http.body"].(string); !strings.Contains(body, "ExamplePanel") {
		t.Errorf("custom probe body = %q", body)
	}
	if _, sent := svc.Custom[ProbeKey(post)]; sent {
		t.Error("POST probe was sent")
	}

	echoHost, echoPort := listen(t, func(c net.Conn) {
		buf := make([]byte, 64)
		n, _ := c.Read(buf)
		if bytes.Equal(buf[:n], []byte("\x00\x01PING")) {
			c.Write([]byte("PONG"))
		}
	})
	ping := rule.Probe{Protocol: "tcp", Send: `\x00\x01PING`, Read: &rule.ReadLimits{MaxBytes: 16, TimeoutMs: 1000}}
	p = testProber(Needs{})
	p.Custom = []CustomProbe{{Key: ProbeKey(ping), Probe: ping}}
	svc = p.Probe(context.Background(), echoHost, echoPort)
	if svc == nil || svc.Custom[ProbeKey(ping)]["service.banner"] != "PONG" {
		t.Errorf("tcp probe result: %+v", svc)
	}
}

// recorder is an HTTP/1.1 server on a raw listener that answers every request
// it can parse, pipelined ones included, and records method and target.
func recorder(t *testing.T) (string, int, func() []string) {
	t.Helper()
	var mu sync.Mutex
	var seen []string
	host, port := listen(t, func(c net.Conn) {
		c.SetDeadline(time.Now().Add(2 * time.Second))
		br := bufio.NewReader(c)
		for {
			req, err := http.ReadRequest(br)
			if err != nil {
				return
			}
			mu.Lock()
			seen = append(seen, req.Method+" "+req.RequestURI)
			mu.Unlock()
			io.Copy(io.Discard, req.Body)
			c.Write([]byte("HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok"))
		}
	})
	return host, port, func() []string {
		mu.Lock()
		defer mu.Unlock()
		return append([]string(nil), seen...)
	}
}

// Probes from third-party rules must not smuggle in a second request,
// another method or credentials, even if they skipped athar verify.
func TestUnsafeProbesAreNotSent(t *testing.T) {
	get := func(path string, headers map[string]string) rule.Probe {
		return rule.Probe{Protocol: "http", Request: &rule.HTTPRequest{Path: path, Headers: headers}}
	}
	for name, pr := range map[string]rule.Probe{
		"crlf in path":    get("/ HTTP/1.1\r\nHost: x\r\n\r\nDELETE /admin/users/1", nil),
		"crlf in header":  get("/", map[string]string{"X-A": "1\r\n\r\nDELETE /admin/users/2 HTTP/1.1\r\nHost: x"}),
		"absolute url":    get("http://127.0.0.1/other", nil),
		"authorization":   get("/", map[string]string{"Authorization": "Basic YWRtaW46YWRtaW4="}),
		"method override": get("/", map[string]string{"X-HTTP-Method-Override": "DELETE"}),
		"tcp post":        {Protocol: "tcp", Send: `POST /api/delete HTTP/1.1\r\nHost: x\r\nContent-Length: 0\r\n\r\n`},
	} {
		host, port, seen := recorder(t)
		svc := &Service{Host: host, IP: host, Port: port}
		if f := testProber(Needs{}).custom(context.Background(), svc, pr); f != nil {
			t.Errorf("%s: probe was sent and got %v", name, f)
		}
		time.Sleep(50 * time.Millisecond)
		if got := seen(); len(got) > 0 {
			t.Errorf("%s: server received %q", name, got)
		}
	}

	// A safe probe still goes out, as one request.
	host, port, seen := recorder(t)
	svc := &Service{Host: host, IP: host, Port: port}
	if f := testProber(Needs{}).custom(context.Background(), svc, get("/api/version", map[string]string{"Accept": "application/json"})); f == nil {
		t.Error("safe probe got no response")
	}
	time.Sleep(50 * time.Millisecond)
	if got := seen(); len(got) != 1 || got[0] != "GET /api/version" {
		t.Errorf("server received %q, want one GET /api/version", got)
	}
}

func TestCheckRequest(t *testing.T) {
	for _, tt := range []struct {
		method, path string
		headers      map[string]string
		ok           bool
	}{
		{"GET", "/favicon.ico", nil, true},
		{"GET", "/a?b=c", map[string]string{"Accept": "text/html; q=0.9\t"}, true},
		{"GET", "/ HTTP/1.1\r\n\r\nDELETE /x", nil, false},
		{"GET", "/a b", nil, false},
		{"DELETE /x HTTP/1.1\r\n\r\nGET", "/", nil, false},
		{"GET", "/", map[string]string{"X-A": "1\r\nX-B: 2"}, false},
		{"GET", "/", map[string]string{"X-A\r\nX-B": "2"}, false},
		{"GET", "/", map[string]string{"X-A: 1\r\nX": "2"}, false},
	} {
		if err := checkRequest(tt.method, tt.path, tt.headers); (err == nil) != tt.ok {
			t.Errorf("checkRequest(%q, %q, %q) = %v, want ok=%v", tt.method, tt.path, tt.headers, err, tt.ok)
		}
	}
}

// A header line that never ends must not be read past the header limit: the
// read stops at maxHeader instead of running until the deadline.
func TestEndlessHeaderLine(t *testing.T) {
	host, port := listen(t, func(c net.Conn) {
		bufio.NewReader(c).ReadString('\n')
		c.Write([]byte("HTTP/1.1 200 OK\r\nX-Junk: "))
		chunk := bytes.Repeat([]byte("a"), 64<<10)
		for range 64 { // 4 MiB, no newline
			if _, err := c.Write(chunk); err != nil {
				return
			}
		}
		time.Sleep(5 * time.Second)
	})
	conn, err := net.Dial("tcp", net.JoinHostPort(host, strconv.Itoa(port)))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(4 * time.Second))
	start := time.Now()
	_, err = httpExchange(conn, host, "GET", "/", nil, "athar-test")
	if err == nil || !strings.Contains(err.Error(), "header block larger than") {
		t.Fatalf("err = %v, want the header limit", err)
	}
	if d := time.Since(start); d > 2*time.Second {
		t.Errorf("took %v; the read should stop at the limit, not at the deadline", d)
	}
}

// A header line longer than the read buffer is still one line: its end must
// not be taken for the blank line that ends the header block.
func TestLongHeaderLine(t *testing.T) {
	long := strings.Repeat("a", 4096-len("X-Long: ")) // the line fills the 4 KiB buffer; "\r\n" comes alone
	host, port := listen(t, func(c net.Conn) {
		bufio.NewReader(c).ReadString('\n')
		c.Write([]byte("HTTP/1.1 200 OK\r\nX-Long: " + long + "\r\nX-After: yes\r\nContent-Length: 2\r\n\r\nok"))
	})
	conn, err := net.Dial("tcp", net.JoinHostPort(host, strconv.Itoa(port)))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(2 * time.Second))
	resp, err := httpExchange(conn, host, "GET", "/", nil, "athar-test")
	if err != nil {
		t.Fatal(err)
	}
	if resp.header.Get("X-Long") != long || resp.header.Get("X-After") != "yes" || string(resp.body) != "ok" {
		t.Errorf("X-Long %d bytes, X-After %q, body %q", len(resp.header.Get("X-Long")), resp.header.Get("X-After"), resp.body)
	}
	if raw := string(resp.headerRaw); !strings.HasSuffix(raw, "X-After: yes\r\nContent-Length: 2\r\n\r\n") {
		t.Errorf("http.headers_raw ends with %q", raw[max(0, len(raw)-40):])
	}
}
