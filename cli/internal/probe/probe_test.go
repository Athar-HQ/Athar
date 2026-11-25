package probe

import (
	"bytes"
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"reflect"
	"strconv"
	"strings"
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

func TestUnescape(t *testing.T) {
	got, err := Unescape(`\x00\x01PING\r\n\\`)
	if err != nil || string(got) != "\x00\x01PING\r\n\\" {
		t.Errorf("got %q, %v", got, err)
	}
	for _, bad := range []string{`\x0`, `\xzz`, `\q`, `abc\`} {
		if _, err := Unescape(bad); err == nil {
			t.Errorf("Unescape(%q): want error", bad)
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
