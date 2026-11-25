package rule

import (
	"encoding/hex"
	"fmt"
	"regexp"
	"strings"
)

// Probes must be safe by construction (spec section 4). Rules come from third
// parties, so athar verify reports every reason Unsafe gives as an error, and
// the scanner sends no probe that has one.

var (
	safeMethods = set("GET", "HEAD", "OPTIONS")

	// unsafeHeaders would send credentials, announce a body, or ask the server
	// to treat the request as another method.
	unsafeHeaders = set("authorization", "proxy-authorization", "cookie",
		"content-length", "transfer-encoding",
		"x-http-method-override", "x-http-method", "x-method-override")

	// requestLine finds an HTTP request line at the start of any line of a
	// raw payload, so pipelined requests are found too.
	requestLine = regexp.MustCompile(`(?m)^[\t ]*([A-Za-z]+)[\t ]+\S+[\t ]+(?i:HTTP)/`)
	headerLine  = regexp.MustCompile(`(?m)^[\t ]*([!#$%&'*+.^_|~0-9A-Za-z` + "`" + `-]+)[\t ]*:`)
)

// Unsafe lists why a probe is not safe to send; nil means it is safe. An
// http probe must use GET, HEAD or OPTIONS, a path that starts with "/", and
// headers without line breaks, credentials, a body or a method override. A
// tcp probe's payload is checked for HTTP requests that break the same
// rules. That check is a heuristic: it can't recognise state-changing
// commands of other protocols.
func (p Probe) Unsafe() []string {
	var why []string
	switch strings.ToLower(p.Protocol) {
	case "http":
		r := p.Request
		if r == nil {
			return nil
		}
		if r.Method != "" && !safeMethods[strings.ToUpper(r.Method)] {
			why = append(why, fmt.Sprintf("method %q is not a safe method (GET, HEAD, OPTIONS)", r.Method))
		}
		if r.Path != "" && !validPath(r.Path) {
			why = append(why, fmt.Sprintf("path %q must start with / and contain no spaces, line breaks or other control characters", r.Path))
		}
		for _, name := range sortedKeys(r.Headers) {
			switch {
			case !validHeaderName(name):
				why = append(why, fmt.Sprintf("header name %q is not a valid HTTP token", name))
			case unsafeHeaders[strings.ToLower(name)]:
				why = append(why, fmt.Sprintf("header %q is not allowed: probes send no credentials, no body and no method override", name))
			}
			if !validHeaderValue(r.Headers[name]) {
				why = append(why, fmt.Sprintf("header %q: the value contains a line break or another control character", name))
			}
		}
	case "tcp":
		payload, err := Unescape(p.Send)
		if err != nil {
			return nil // a payload that doesn't decode is never sent
		}
		var http bool
		for _, m := range requestLine.FindAllSubmatch(payload, -1) {
			http = true
			if method := strings.ToUpper(string(m[1])); !safeMethods[method] {
				why = append(why, fmt.Sprintf("send contains an HTTP %s request; probes only send GET, HEAD or OPTIONS", method))
			}
		}
		if http {
			for _, m := range headerLine.FindAllSubmatch(payload, -1) {
				if name := string(m[1]); unsafeHeaders[strings.ToLower(name)] {
					why = append(why, fmt.Sprintf("send contains the HTTP header %q: probes send no credentials, no body and no method override", name))
				}
			}
		}
	}
	return why
}

// validPath accepts an origin-form request target. An absolute URL would ask
// a proxy to fetch another host, and spaces or control characters would end
// the request line.
func validPath(s string) bool {
	if !strings.HasPrefix(s, "/") {
		return false
	}
	for i := 0; i < len(s); i++ {
		if s[i] <= ' ' || s[i] == 0x7f {
			return false
		}
	}
	return true
}

// validHeaderName reports whether s is an HTTP token (RFC 9110, section 5.6.2).
func validHeaderName(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || strings.IndexByte("!#$%&'*+-.^_`|~", c) >= 0) {
			return false
		}
	}
	return true
}

// validHeaderValue rejects control characters other than tab.
func validHeaderValue(s string) bool {
	for i := 0; i < len(s); i++ {
		if c := s[i]; (c < ' ' && c != '\t') || c == 0x7f {
			return false
		}
	}
	return true
}

// Unescape decodes the escapes used in probe payloads, as in
// nmap-service-probes: \xHH, \0, \r, \n, \t and \\.
func Unescape(s string) ([]byte, error) {
	var out []byte
	for i := 0; i < len(s); i++ {
		if s[i] != '\\' {
			out = append(out, s[i])
			continue
		}
		if i+1 >= len(s) {
			return nil, fmt.Errorf("payload ends with a backslash")
		}
		i++
		switch s[i] {
		case 'x':
			if i+2 >= len(s) {
				return nil, fmt.Errorf("incomplete \\x escape")
			}
			b, err := hex.DecodeString(s[i+1 : i+3])
			if err != nil {
				return nil, fmt.Errorf("invalid \\x escape %q", s[i-1:i+3])
			}
			out = append(out, b[0])
			i += 2
		case '0':
			out = append(out, 0)
		case 'r':
			out = append(out, '\r')
		case 'n':
			out = append(out, '\n')
		case 't':
			out = append(out, '\t')
		case '\\':
			out = append(out, '\\')
		default:
			return nil, fmt.Errorf("unknown escape \\%c", s[i])
		}
	}
	return out, nil
}
