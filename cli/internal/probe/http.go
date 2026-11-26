package probe

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"crypto/md5"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"hash"
	"html"
	"io"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/Athar-HQ/Athar/cli/internal/eval"
)

const (
	// MaxBody is how much of a body is kept (spec section 5).
	MaxBody = 1 << 20
	// maxHashBody is how much of a body is read to hash it. The hashes are
	// of the complete body, so a longer body has none.
	maxHashBody = 16 << 20
	// maxHeader limits the raw header block.
	maxHeader = 64 << 10
)

// httpResponse is one parsed HTTP response.
type httpResponse struct {
	status    int
	headerRaw []byte
	header    http.Header
	body      []byte // the first MaxBody bytes
	// complete says that the body was read to its end. Only then are the
	// hashes of the body set.
	complete bool
	mmh3     int32
	sha256   string
}

// httpExchange sends one request on conn and reads the response. The
// connection is used for this request only (Connection: close). The body is
// also written to hashes, all of it if the response ends up complete.
func httpExchange(conn net.Conn, hostHeader, method, path string, headers map[string]string, ua string, hashes ...io.Writer) (*httpResponse, error) {
	if err := checkRequest(method, path, headers); err != nil {
		return nil, err
	}
	var req bytes.Buffer
	fmt.Fprintf(&req, "%s %s HTTP/1.1\r\nHost: %s\r\nUser-Agent: %s\r\nAccept: */*\r\nConnection: close\r\n", method, path, hostHeader, ua)
	names := make([]string, 0, len(headers))
	for k := range headers {
		names = append(names, k)
	}
	sort.Strings(names)
	for _, k := range names {
		if strings.EqualFold(k, "Host") || strings.EqualFold(k, "Connection") {
			continue
		}
		fmt.Fprintf(&req, "%s: %s\r\n", k, headers[k])
	}
	req.WriteString("\r\n")
	if _, err := conn.Write(req.Bytes()); err != nil {
		return nil, err
	}

	// Keep the header block exactly as received, then let net/http parse it.
	// Lines are read in pieces of at most the buffer size, so a line without
	// an end can't grow past maxHeader. Interim 1xx responses come before
	// the final one and are skipped; maxHeader limits all blocks together.
	br := bufio.NewReader(conn)
	var raw bytes.Buffer
	var resp *http.Response
	for skipped := 0; ; skipped += raw.Len() {
		raw.Reset()
		start := 0 // where the current line starts in raw
		for {
			piece, err := br.ReadSlice('\n')
			raw.Write(piece)
			if skipped+raw.Len() > maxHeader {
				return nil, fmt.Errorf("header block larger than %d bytes", maxHeader)
			}
			if errors.Is(err, bufio.ErrBufferFull) {
				continue // the line goes on
			}
			if err != nil {
				return nil, fmt.Errorf("reading headers: %w", err)
			}
			if len(bytes.TrimRight(raw.Bytes()[start:], "\r\n")) == 0 {
				break
			}
			start = raw.Len()
		}
		if !bytes.HasPrefix(raw.Bytes(), []byte("HTTP/")) {
			return nil, fmt.Errorf("not an HTTP response")
		}
		var err error
		resp, err = http.ReadResponse(bufio.NewReader(io.MultiReader(bytes.NewReader(raw.Bytes()), br)), &http.Request{Method: method})
		if err != nil {
			return nil, err
		}
		if resp.StatusCode/100 != 1 || resp.StatusCode == http.StatusSwitchingProtocols {
			break
		}
	}

	var body io.Reader = resp.Body
	limit := int64(maxHashBody)
	if strings.EqualFold(resp.Header.Get("Content-Encoding"), "gzip") {
		body = gunzip(resp.Body)
	} else if resp.ContentLength > limit {
		limit = MaxBody // too long to hash: read no more than is kept
	}
	// The first MaxBody bytes are kept and the complete body is hashed as it
	// arrives. A body cut short by a timeout or reset still counts for what
	// arrived, but has no hashes. The body is not closed: closing reads on
	// to its end, and the caller closes the connection.
	r := &httpResponse{status: resp.StatusCode, headerRaw: raw.Bytes(), header: resp.Header}
	var mmh3 mmh3Sum
	sha := sha256.New()
	w := io.MultiWriter(append([]io.Writer{(*bodyHead)(&r.body), &mmh3, sha}, hashes...)...)
	if n, err := io.Copy(w, io.LimitReader(body, limit+1)); err == nil && n <= limit {
		r.complete, r.mmh3, r.sha256 = true, mmh3.Sum(), hex.EncodeToString(sha.Sum(nil))
	}
	return r, nil
}

// bodyHead keeps the first MaxBody bytes written to it.
type bodyHead []byte

func (b *bodyHead) Write(p []byte) (int, error) {
	*b = append(*b, p[:min(len(p), MaxBody-len(*b))]...)
	return len(p), nil
}

// gunzip decodes a gzip body. A body without a valid gzip header is returned
// as received: gzip.NewReader reads ahead, so the bytes it took are replayed.
func gunzip(r io.Reader) io.Reader {
	rec := &replayReader{r: r, on: true}
	zr, err := gzip.NewReader(rec)
	if err != nil {
		return io.MultiReader(bytes.NewReader(rec.buf.Bytes()), r)
	}
	rec.on, rec.buf = false, bytes.Buffer{}
	return zr
}

// replayReader keeps a copy of what is read through it while on.
type replayReader struct {
	r   io.Reader
	buf bytes.Buffer
	on  bool
}

func (c *replayReader) Read(p []byte) (int, error) {
	n, err := c.r.Read(p)
	if c.on {
		c.buf.Write(p[:n])
	}
	return n, err
}

// checkRequest refuses a request whose parts would end the request line or a
// header early, which would add headers or a second request. Custom probes
// are checked against the full rules (rule.Probe.Unsafe) before they get
// here; this guards every request the prober sends.
func checkRequest(method, path string, headers map[string]string) error {
	for _, s := range []string{method, path} {
		if strings.ContainsFunc(s, func(r rune) bool { return r <= ' ' || r == 0x7f }) {
			return fmt.Errorf("refusing to send request line part %q", s)
		}
	}
	for k, v := range headers {
		if strings.ContainsAny(k, "\r\n\x00: \t") || strings.ContainsAny(v, "\r\n\x00") {
			return fmt.Errorf("refusing to send header %q", k)
		}
	}
	return nil
}

// fields stores the response in taxonomy fields.
func (r *httpResponse) fields(f eval.Fields) {
	f["service.protocol"] = "http"
	f["http.status_code"] = r.status
	f["http.headers_raw"] = string(r.headerRaw)
	for key, values := range rawHeaders(r.headerRaw) {
		if len(values) == 1 {
			f[key] = values[0]
			continue
		}
		f[key] = values
	}
	// The text fields read the decoded body, the hashes the bytes as received.
	text := decodeBody(r.header.Get("Content-Type"), r.body)
	f["http.body"] = string(text)
	if r.complete {
		f["http.body.mmh3"] = int(r.mmh3)
		f["http.body.sha256"] = r.sha256
	}
	if t, ok := title(text); ok {
		f["http.title"] = t
	}
}

// rawHeaders returns the values of every header in a raw header block, in
// order, keyed by field name (http.headers.<lowercase name>). net/http's own
// header map is not used: it drops Transfer-Encoding, Trailer and
// "Connection: close", merges repeated Content-Length headers and adds a
// Cache-Control to "Pragma: no-cache". Lines are read as net/http reads them:
// spaces and tabs around a value are removed, and a folded line is joined to
// the one before with a single space. The block has passed http.ReadResponse,
// so every header line has a name and a colon.
func rawHeaders(raw []byte) map[string][]any {
	var kvs []string
	for _, line := range strings.Split(string(raw), "\n")[1:] { // [0] is the status line
		line = strings.TrimSuffix(line, "\r")
		if line == "" {
			break
		}
		if (line[0] == ' ' || line[0] == '\t') && len(kvs) > 0 {
			kvs[len(kvs)-1] += " " + strings.Trim(line, " \t")
			continue
		}
		kvs = append(kvs, strings.Trim(line, " \t"))
	}
	headers := map[string][]any{}
	for _, kv := range kvs {
		name, value, _ := strings.Cut(kv, ":")
		key := "http.headers." + strings.ToLower(name)
		headers[key] = append(headers[key], strings.TrimLeft(value, " \t"))
	}
	return headers
}

var titleRe = regexp.MustCompile(`(?is)<title[^>]*>(.*?)</title>`)

// title returns the HTML title, entity-decoded and whitespace-collapsed.
func title(body []byte) (string, bool) {
	m := titleRe.FindSubmatch(body)
	if m == nil {
		return "", false
	}
	return strings.Join(strings.Fields(html.UnescapeString(string(m[1]))), " "), true
}

var (
	linkRe = regexp.MustCompile(`(?is)<link\b[^>]*>`)
	relRe  = regexp.MustCompile(`(?is)\brel\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s>]+))`)
	hrefRe = regexp.MustCompile(`(?is)\bhref\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s>]+))`)
)

func attr(re *regexp.Regexp, tag []byte) string {
	m := re.FindSubmatch(tag)
	if m == nil {
		return ""
	}
	for _, g := range m[1:] {
		if len(g) > 0 {
			return html.UnescapeString(string(g))
		}
	}
	return ""
}

// faviconRef returns the href of the first <link rel="icon"> (also
// "shortcut icon"), or "" if there is none.
func faviconRef(body []byte) string {
	for _, tag := range linkRe.FindAll(body, -1) {
		for _, tok := range strings.Fields(strings.ToLower(attr(relRe, tag))) {
			if tok == "icon" {
				return strings.TrimSpace(attr(hrefRe, tag))
			}
		}
	}
	return ""
}

// faviconSource resolves a favicon reference. It returns either inline icon
// bytes (data: URI) or a request path on the same service. References to
// other hosts fall back to /favicon.ico, because the scanner only talks to
// the target. So do references without a path, such as "#" or "?v=2": they
// point at the page itself, which is not an icon.
func faviconSource(ref, host string, port int) (path string, inline []byte) {
	if ref == "" {
		return "/favicon.ico", nil
	}
	if strings.HasPrefix(strings.ToLower(ref), "data:") {
		if b, ok := decodeDataURI(ref); ok {
			return "", b
		}
		return "/favicon.ico", nil
	}
	u, err := url.Parse(ref)
	if err != nil || u.Path == "" {
		return "/favicon.ico", nil
	}
	if u.Host != "" {
		h, p := u.Hostname(), u.Port()
		if !strings.EqualFold(h, host) || (p != "" && p != strconv.Itoa(port)) {
			return "/favicon.ico", nil
		}
	}
	base, _ := url.Parse("/")
	return base.ResolveReference(&url.URL{Path: u.Path, RawPath: u.RawPath, RawQuery: u.RawQuery}).RequestURI(), nil
}

func decodeDataURI(s string) ([]byte, bool) {
	meta, data, ok := strings.Cut(s[len("data:"):], ",")
	if !ok {
		return nil, false
	}
	if strings.HasSuffix(strings.ToLower(meta), ";base64") {
		b, err := base64.StdEncoding.DecodeString(strings.Join(strings.Fields(data), ""))
		return b, err == nil
	}
	b, err := url.PathUnescape(data)
	return []byte(b), err == nil
}

// faviconFields stores the favicon hashes.
func faviconFields(f eval.Fields, icon []byte) {
	s := newIconSum()
	s.Write(icon)
	s.fields(f)
}

// iconSum computes the favicon hashes over an icon written in pieces.
type iconSum struct {
	md5, sha256 hash.Hash
	mmh3        mmh3Sum // over the base64 lines, as FaviconMMH3
	line        []byte  // the bytes of the next base64 line, fewer than 57
	n           int
}

func newIconSum() *iconSum {
	return &iconSum{md5: md5.New(), sha256: sha256.New()}
}

func (s *iconSum) Write(p []byte) (int, error) {
	s.md5.Write(p)
	s.sha256.Write(p)
	s.n += len(p)
	for rest := p; len(rest) > 0; {
		c := min(len(rest), 57-len(s.line))
		s.line = append(s.line, rest[:c]...)
		rest = rest[c:]
		if len(s.line) == 57 { // 76 characters
			s.endLine()
		}
	}
	return len(p), nil
}

func (s *iconSum) endLine() {
	enc := base64.StdEncoding.AppendEncode(make([]byte, 0, 77), s.line)
	s.mmh3.Write(append(enc, '\n'))
	s.line = s.line[:0]
}

// fields ends the icon and stores its hashes. An empty icon has none.
func (s *iconSum) fields(f eval.Fields) {
	if s.n == 0 {
		return
	}
	if len(s.line) > 0 {
		s.endLine()
	}
	f["http.favicon.mmh3"] = int(s.mmh3.Sum())
	f["http.favicon.md5"] = hex.EncodeToString(s.md5.Sum(nil))
	f["http.favicon.sha256"] = hex.EncodeToString(s.sha256.Sum(nil))
}
