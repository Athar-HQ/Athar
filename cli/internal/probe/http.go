package probe

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"encoding/base64"
	"fmt"
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
	// maxHeader limits the raw header block.
	maxHeader = 64 << 10
)

// httpResponse is one parsed HTTP response.
type httpResponse struct {
	status    int
	headerRaw []byte
	header    http.Header
	body      []byte
}

// httpExchange sends one request on conn and reads the response. The
// connection is used for this request only (Connection: close).
func httpExchange(conn net.Conn, hostHeader, method, path string, headers map[string]string, ua string) (*httpResponse, error) {
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
	br := bufio.NewReader(conn)
	var raw bytes.Buffer
	for {
		line, err := br.ReadBytes('\n')
		raw.Write(line)
		if err != nil {
			return nil, fmt.Errorf("reading headers: %w", err)
		}
		if raw.Len() > maxHeader {
			return nil, fmt.Errorf("header block larger than %d bytes", maxHeader)
		}
		if len(bytes.TrimRight(line, "\r\n")) == 0 {
			break
		}
	}
	if !bytes.HasPrefix(raw.Bytes(), []byte("HTTP/")) {
		return nil, fmt.Errorf("not an HTTP response")
	}
	resp, err := http.ReadResponse(bufio.NewReader(io.MultiReader(bytes.NewReader(raw.Bytes()), br)), &http.Request{Method: method})
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var body io.Reader = resp.Body
	if strings.EqualFold(resp.Header.Get("Content-Encoding"), "gzip") {
		if zr, err := gzip.NewReader(resp.Body); err == nil {
			body = zr
		}
	}
	// A body cut short by a timeout or reset still counts; keep what arrived.
	b, _ := io.ReadAll(io.LimitReader(body, MaxBody))

	return &httpResponse{status: resp.StatusCode, headerRaw: raw.Bytes(), header: resp.Header, body: b}, nil
}

// fields stores the response in taxonomy fields.
func (r *httpResponse) fields(f eval.Fields) {
	f["service.protocol"] = "http"
	f["http.status_code"] = r.status
	f["http.headers_raw"] = string(r.headerRaw)
	for name, values := range r.header {
		key := "http.headers." + strings.ToLower(name)
		if len(values) == 1 {
			f[key] = values[0]
			continue
		}
		list := make([]any, len(values))
		for i, v := range values {
			list[i] = v
		}
		f[key] = list
	}
	f["http.body"] = string(r.body)
	f["http.body.mmh3"] = int(MMH3(r.body))
	f["http.body.sha256"] = sha256Hex(r.body)
	if t, ok := title(r.body); ok {
		f["http.title"] = t
	}
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
// the target.
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
	if err != nil {
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
	if len(icon) == 0 {
		return
	}
	f["http.favicon.mmh3"] = int(FaviconMMH3(icon))
	f["http.favicon.md5"] = md5Hex(icon)
	f["http.favicon.sha256"] = sha256Hex(icon)
}
