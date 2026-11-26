package probe

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"net/netip"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/Athar-HQ/Athar/cli/internal/eval"
	"github.com/Athar-HQ/Athar/cli/internal/rule"
)

// maxBanner is how many bytes of a banner are kept.
const maxBanner = 8 << 10

// Needs says which parts of the baseline probe the loaded rules use, so the
// prober only does work that can change a result.
type Needs struct {
	Banner  bool // wait for a server-first banner (SSH, FTP, SMTP, …)
	TLS     bool // try a TLS handshake
	HTTP    bool // send GET /
	Favicon bool // fetch the favicon
}

// CustomProbe is a rule-declared probe. Key identifies identical probes across
// rules, so each is sent once per service.
type CustomProbe struct {
	Key   string
	Probe rule.Probe
}

// ProbeKey returns a key that is equal for probes that send the same request.
func ProbeKey(p rule.Probe) string {
	var b strings.Builder
	b.WriteString(strings.ToLower(p.Protocol))
	if r := p.Request; r != nil {
		fmt.Fprintf(&b, "|%s|%s", strings.ToUpper(r.Method), r.Path)
		for _, k := range sortedKeys(r.Headers) {
			fmt.Fprintf(&b, "|%s=%s", strings.ToLower(k), r.Headers[k])
		}
	}
	fmt.Fprintf(&b, "|%q", p.Send)
	if p.Read != nil {
		fmt.Fprintf(&b, "|%d|%d", p.Read.MaxBytes, p.Read.TimeoutMs)
	}
	return b.String()
}

// Prober checks one host and port at a time. It is safe for concurrent use.
type Prober struct {
	Connect    time.Duration // TCP connect timeout; 0 means Timeout
	Timeout    time.Duration // handshake and read timeout
	BannerWait time.Duration // how long to wait for a server-first banner
	UserAgent  string
	Needs      Needs
	Custom     []CustomProbe // sent on every open port; empty unless enabled

	// Limit is called before every new connection, e.g. to apply a rate
	// limit. It may be nil.
	Limit func(context.Context) error
}

// Service is what the prober observed on one open port.
type Service struct {
	Host   string // as given: IP address or hostname
	IP     string // the address that answered
	Port   int
	TLS    bool
	Fields eval.Fields            // baseline probe
	Custom map[string]eval.Fields // custom probes, by key
}

// Probe checks host:port. It returns nil if the port is not open.
func (p *Prober) Probe(ctx context.Context, host string, port int) *Service {
	conn, err := p.dial(ctx, host, port)
	if err != nil {
		return nil
	}
	svc := &Service{Host: host, Port: port, Fields: eval.Fields{}, Custom: map[string]eval.Fields{}}
	if ap, err := netip.ParseAddrPort(conn.RemoteAddr().String()); err == nil {
		svc.IP = ap.Addr().Unmap().String()
	} else {
		svc.IP = host
	}
	f := svc.Fields
	f["service.port"] = port
	f["service.transport"] = "tcp"

	p.baseline(ctx, svc, conn)

	for _, cp := range p.Custom {
		if cf := p.custom(ctx, svc, cp.Probe); cf != nil {
			svc.Custom[cp.Key] = cf
		}
	}
	return svc
}

// baseline runs the default probe on a fresh connection: banner, then TLS,
// then HTTP, reusing the connection while nothing has been sent on it.
func (p *Prober) baseline(ctx context.Context, svc *Service, conn net.Conn) {
	f := svc.Fields

	// 1. Server-first protocols send a banner before the client says anything.
	if p.Needs.Banner {
		if b := readBanner(conn, p.BannerWait); len(b) > 0 {
			bannerFields(f, b)
			conn.Close()
			return
		}
	}

	// 2. TLS on the same, still unused connection.
	if p.Needs.TLS {
		tc := tls.Client(conn, p.tlsConfig(svc.Host))
		tc.SetDeadline(time.Now().Add(p.Timeout))
		if err := tc.HandshakeContext(ctx); err == nil {
			svc.TLS = true
			tlsFields(f, tc.ConnectionState())
			if p.Needs.Banner {
				if b := readBanner(tc, p.BannerWait); len(b) > 0 {
					bannerFields(f, b)
					tc.Close()
					return
				}
			}
			if p.Needs.HTTP {
				p.http(ctx, svc, tc)
			}
			tc.Close()
			return
		}
		// A failed handshake leaves the connection unusable.
		conn.Close()
		conn = nil
	}

	// 3. Plaintext HTTP.
	if !p.Needs.HTTP {
		if conn != nil {
			conn.Close()
		}
		return
	}
	if conn == nil {
		var err error
		if conn, err = p.dial(ctx, svc.IP, svc.Port); err != nil {
			return
		}
	}
	p.http(ctx, svc, conn)
	conn.Close()
}

// http sends GET / on conn and, if needed, fetches the favicon.
func (p *Prober) http(ctx context.Context, svc *Service, conn net.Conn) {
	conn.SetDeadline(time.Now().Add(p.Timeout))
	resp, err := httpExchange(conn, hostHeader(svc), "GET", "/", nil, p.UserAgent)
	if err != nil {
		return
	}
	resp.fields(svc.Fields)
	if !p.Needs.Favicon {
		return
	}
	path, inline := faviconSource(faviconRef(resp.body), svc.Host, svc.Port)
	if inline != nil {
		faviconFields(svc.Fields, inline)
		return
	}
	ic, err := p.connect(ctx, svc)
	if err != nil {
		return
	}
	defer ic.Close()
	// Like the body hashes, the favicon hashes are of the complete icon.
	sum := newIconSum()
	icon, err := httpExchange(ic, hostHeader(svc), "GET", path, nil, p.UserAgent, sum)
	if err == nil && icon.status == 200 && icon.complete {
		sum.fields(svc.Fields)
	}
}

// custom sends one rule-declared probe and returns the fields it produced.
func (p *Prober) custom(ctx context.Context, svc *Service, pr rule.Probe) eval.Fields {
	if len(pr.Unsafe()) > 0 {
		return nil // athar verify rejects these probes; never send them
	}
	conn, err := p.connect(ctx, svc)
	if err != nil {
		return nil
	}
	defer conn.Close()
	f := eval.Fields{"service.port": svc.Port, "service.transport": "tcp"}

	switch strings.ToLower(pr.Protocol) {
	case "http":
		method, path := "GET", "/"
		var headers map[string]string
		if r := pr.Request; r != nil {
			if r.Method != "" {
				method = strings.ToUpper(r.Method)
			}
			if r.Path != "" {
				path = r.Path
			}
			headers = r.Headers
		}
		resp, err := httpExchange(conn, hostHeader(svc), method, path, headers, p.UserAgent)
		if err != nil {
			return nil
		}
		resp.fields(f)
	case "tcp":
		maxBytes, wait := maxBanner, p.Timeout
		if r := pr.Read; r != nil {
			if r.MaxBytes > 0 {
				maxBytes = min(r.MaxBytes, maxBanner)
			}
			if r.TimeoutMs > 0 {
				wait = time.Duration(r.TimeoutMs) * time.Millisecond
			}
		}
		if pr.Send != "" {
			payload, err := rule.Unescape(pr.Send)
			if err != nil {
				return nil
			}
			if _, err := conn.Write(payload); err != nil {
				return nil
			}
		}
		b := readBanner(conn, wait)
		if len(b) > maxBytes {
			b = b[:maxBytes]
		}
		if len(b) == 0 {
			return nil
		}
		bannerFields(f, b)
	default:
		return nil
	}
	return f
}

// connect opens a new connection to an already observed service, with TLS if
// the service spoke TLS.
func (p *Prober) connect(ctx context.Context, svc *Service) (net.Conn, error) {
	conn, err := p.dial(ctx, svc.IP, svc.Port)
	if err != nil {
		return nil, err
	}
	conn.SetDeadline(time.Now().Add(p.Timeout))
	if !svc.TLS {
		return conn, nil
	}
	tc := tls.Client(conn, p.tlsConfig(svc.Host))
	if err := tc.HandshakeContext(ctx); err != nil {
		conn.Close()
		return nil, err
	}
	return tc, nil
}

func (p *Prober) dial(ctx context.Context, host string, port int) (net.Conn, error) {
	if p.Limit != nil {
		if err := p.Limit(ctx); err != nil {
			return nil, err
		}
	}
	timeout := p.Connect
	if timeout <= 0 {
		timeout = p.Timeout
	}
	d := net.Dialer{Timeout: timeout}
	return d.DialContext(ctx, "tcp", net.JoinHostPort(host, strconv.Itoa(port)))
}

// allCipherSuites includes the insecure ones, so old servers still complete
// a handshake. The scanner only observes; it sends nothing confidential.
var allCipherSuites = func() []uint16 {
	var ids []uint16
	for _, s := range tls.CipherSuites() {
		ids = append(ids, s.ID)
	}
	for _, s := range tls.InsecureCipherSuites() {
		ids = append(ids, s.ID)
	}
	return ids
}()

func (p *Prober) tlsConfig(host string) *tls.Config {
	cfg := &tls.Config{
		InsecureSkipVerify: true, // fingerprinting, not trusting
		MinVersion:         tls.VersionTLS10,
		CipherSuites:       allCipherSuites,
	}
	if _, err := netip.ParseAddr(host); err != nil {
		cfg.ServerName = host // SNI only for hostnames, as for an IP-based crawl
	}
	return cfg
}

// hostHeader is the Host header: the target as given, with the port unless
// it is the scheme's default.
func hostHeader(svc *Service) string {
	h := svc.Host
	if a, err := netip.ParseAddr(h); err == nil && a.Is6() {
		h = "[" + h + "]"
	}
	if (svc.TLS && svc.Port == 443) || (!svc.TLS && svc.Port == 80) {
		return h
	}
	return h + ":" + strconv.Itoa(svc.Port)
}

// readBanner waits up to wait for the first bytes, then collects what follows
// shortly after.
func readBanner(conn net.Conn, wait time.Duration) []byte {
	buf := make([]byte, maxBanner)
	conn.SetReadDeadline(time.Now().Add(wait))
	n, _ := conn.Read(buf)
	for n > 0 && n < len(buf) {
		conn.SetReadDeadline(time.Now().Add(250 * time.Millisecond))
		m, err := conn.Read(buf[n:])
		n += m
		if err != nil || m == 0 {
			break
		}
	}
	conn.SetReadDeadline(time.Time{})
	return buf[:n]
}

func bannerFields(f eval.Fields, b []byte) {
	f["service.banner"] = string(b)
	if bytes.HasPrefix(b, []byte("SSH-")) {
		line, _, _ := bytes.Cut(b, []byte("\n"))
		f["ssh.banner"] = string(bytes.TrimRight(line, "\r"))
		f["service.protocol"] = "ssh"
	}
}

func tlsFields(f eval.Fields, st tls.ConnectionState) {
	f["tls.version"] = tls.VersionName(st.Version)
	f["tls.cipher"] = tls.CipherSuiteName(st.CipherSuite)
	if st.NegotiatedProtocol != "" {
		f["tls.alpn"] = st.NegotiatedProtocol
	}
	if len(st.PeerCertificates) == 0 {
		return
	}
	c := st.PeerCertificates[0]
	setString(f, "tls.cert.subject.cn", c.Subject.CommonName)
	setList(f, "tls.cert.subject.o", c.Subject.Organization)
	setString(f, "tls.cert.subject.dn", c.Subject.String())
	setString(f, "tls.cert.issuer.cn", c.Issuer.CommonName)
	setList(f, "tls.cert.issuer.o", c.Issuer.Organization)
	setString(f, "tls.cert.issuer.dn", c.Issuer.String())
	if c.SerialNumber != nil {
		f["tls.cert.serial"] = c.SerialNumber.Text(16)
	}
	f["tls.cert.sha256"] = sha256Hex(c.Raw)
	f["tls.cert.sha1"] = sha1Hex(c.Raw)
	san := append([]string(nil), c.DNSNames...)
	for _, ip := range c.IPAddresses {
		san = append(san, ip.String())
	}
	setList(f, "tls.cert.san", san)
	f["tls.cert.self_signed"] = selfSigned(c)
}

// selfSigned: subject equals issuer and the signature verifies with the
// certificate's own key. CheckSignatureFrom is not used because it also
// requires the CA flag, which many self-signed leaf certificates lack.
func selfSigned(c *x509.Certificate) bool {
	return bytes.Equal(c.RawSubject, c.RawIssuer) &&
		c.CheckSignature(c.SignatureAlgorithm, c.RawTBSCertificate, c.Signature) == nil
}

func setString(f eval.Fields, key, v string) {
	if v != "" {
		f[key] = v
	}
}

// setList stores one value as a string and several as a list.
func setList(f eval.Fields, key string, values []string) {
	switch len(values) {
	case 0:
	case 1:
		f[key] = values[0]
	default:
		list := make([]any, len(values))
		for i, v := range values {
			list[i] = v
		}
		f[key] = list
	}
}

func sortedKeys(m map[string]string) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}
