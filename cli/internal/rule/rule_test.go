package rule

import (
	"strings"
	"testing"
)

const validRule = `
title: Example
id: 0ce69e91-baee-4475-81ee-4b8eca1a6c3b
status: experimental
target:
  protocol: http
detection:
  sel:
    http.title: Example
  condition: sel
identifies:
  product: Example
  category: web-server
confidence: high
tests:
  - name: hit
    expect: match
    response: { http.title: Example }
  - name: miss
    expect: no_match
    response: { http.title: Other }
`

func TestCheckValid(t *testing.T) {
	r, err := Parse([]byte(validRule), "valid.yml")
	if err != nil {
		t.Fatal(err)
	}
	if p := Check(r); len(p) != 0 {
		t.Errorf("unexpected problems: %v", p)
	}
}

func TestCheckProblems(t *testing.T) {
	tests := []struct {
		replace, with string
		severity      Severity
		want          string
	}{
		{"title: Example\n", "", Error, "missing title"},
		{"0ce69e91-baee-4475-81ee-4b8eca1a6c3b", "not-a-uuid", Error, "UUIDv4"},
		{"0ce69e91-baee-4475-81ee-4b8eca1a6c3b", "0CE69E91-BAEE-4475-81EE-4B8ECA1A6C3B", Error, "UUIDv4"},
		{"status: experimental", "status: beta", Error, "status"},
		{"confidence: high", "confidence: very", Error, "confidence"},
		{"category: web-server", "category: webserver", Error, "identifies.category"},
		{"  product: Example\n", "", Error, "product or a family"},
		{"  protocol: http\n", "  protocol: http\n  tls: maybe\n", Error, "target.tls"},
		{"confidence: high", "confidence: high\nlevel: medium", Warning, `unknown top-level key "level"`},
		{"confidence: high", "confidence: high\nprobes:\n  p:\n    protocol: http\n    request: { method: POST, path: / }", Error, "safe method"},
		{"confidence: high", "confidence: high\nrelated:\n  - id: 0536c409-98ed-4d1d-8e07-7c80b39a4f53\n    type: child-of", Error, "related type"},
		{"    expect: no_match", "    expect: match", Warning, "no_match"},
		{"    response: { http.title: Other }", "    response: { http.title: Other }\n    probes: { css: { http.status_code: 200 } }", Error, `probe "css" is not declared`},
		{"confidence: high", "confidence: high\nidentfies: {}", Warning, "unknown top-level key"},
	}
	for _, tt := range tests {
		src := strings.Replace(validRule, tt.replace, tt.with, 1)
		r, err := Parse([]byte(src), "x.yml")
		if err != nil {
			t.Errorf("%s: %v", tt.want, err)
			continue
		}
		found := false
		for _, p := range Check(r) {
			if p.Severity == tt.severity && strings.Contains(p.Msg, tt.want) {
				found = true
			}
		}
		if !found {
			t.Errorf("replacing %q: no %s containing %q in %v", tt.replace, tt.severity, tt.want, Check(r))
		}
	}
}

func TestParseErrors(t *testing.T) {
	for name, src := range map[string]string{
		"empty":     "",
		"two docs":  validRule + "\n---\n" + validRule,
		"not a map": "- a\n- b\n",
		"bad yaml":  "title: [unclosed\n",
	} {
		if _, err := Parse([]byte(src), name); err == nil {
			t.Errorf("%s: want error", name)
		}
	}
}

func TestCheckSet(t *testing.T) {
	a, _ := Parse([]byte(validRule), "a.yml")
	b, _ := Parse([]byte(validRule), "b.yml")
	variant := strings.Replace(validRule, "0ce69e91-baee-4475-81ee-4b8eca1a6c3b",
		"0536c409-98ed-4d1d-8e07-7c80b39a4f53\nrelated:\n  - id: 11111111-1111-4111-8111-111111111111\n    type: variant-of", 1)
	c, _ := Parse([]byte(variant), "c.yml")

	got := CheckSet([]*Rule{a, b, c})
	if len(got["a.yml"]) != 0 {
		t.Errorf("a.yml: %v", got["a.yml"])
	}
	if len(got["b.yml"]) != 1 || !strings.Contains(got["b.yml"][0].Msg, "already used by a.yml") {
		t.Errorf("b.yml: %v", got["b.yml"])
	}
	if len(got["c.yml"]) != 1 || !strings.Contains(got["c.yml"][0].Msg, "family rule not found") {
		t.Errorf("c.yml: %v", got["c.yml"])
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

// A probe from a third-party rule must not be able to send another method,
// a second request, credentials or a body (spec section 4).
func TestProbeUnsafe(t *testing.T) {
	get := func(path string, headers map[string]string) Probe {
		return Probe{Protocol: "http", Request: &HTTPRequest{Method: "GET", Path: path, Headers: headers}}
	}
	for name, tt := range map[string]struct {
		p    Probe
		want string // "" means safe
	}{
		"default request":       {Probe{Protocol: "http"}, ""},
		"api with accept":       {get("/api/version", map[string]string{"Accept": "application/json"}), ""},
		"head lowercase":        {Probe{Protocol: "http", Request: &HTTPRequest{Method: "head", Path: "/"}}, ""},
		"tcp ping":              {Probe{Protocol: "tcp", Send: `\x00\x00\x00\x01PING`}, ""},
		"tcp safe http":         {Probe{Protocol: "tcp", Send: `GET / HTTP/1.0\r\n\r\n`}, ""},
		"post":                  {Probe{Protocol: "http", Request: &HTTPRequest{Method: "POST", Path: "/"}}, "safe method"},
		"crlf in path":          {get("/ HTTP/1.1\r\nHost: x\r\n\r\nDELETE /admin", nil), "path"},
		"space in path":         {get("/a b", nil), "path"},
		"absolute url":          {get("http://169.254.169.254/latest/meta-data/", nil), "path"},
		"no leading slash":      {get("api/version", nil), "path"},
		"crlf in header value":  {get("/", map[string]string{"X-A": "1\r\n\r\nDELETE /x HTTP/1.1"}), "line break"},
		"crlf in header name":   {get("/", map[string]string{"X-A: 1\r\nX-B": "2"}), "token"},
		"authorization":         {get("/", map[string]string{"Authorization": "Basic YWRtaW46YWRtaW4="}), "credentials"},
		"cookie":                {get("/", map[string]string{"cookie": "session=1"}), "credentials"},
		"content-length":        {get("/", map[string]string{"Content-Length": "5"}), "body"},
		"method override":       {get("/", map[string]string{"X-HTTP-Method-Override": "DELETE"}), "method override"},
		"tcp post":              {Probe{Protocol: "tcp", Send: `POST /api/delete HTTP/1.1\r\nHost: x\r\n\r\n`}, "HTTP POST"},
		"tcp escaped delete":    {Probe{Protocol: "tcp", Send: `\x44ELETE /x HTTP/1.1\r\n\r\n`}, "HTTP DELETE"},
		"tcp pipelined put":     {Probe{Protocol: "tcp", Send: `GET / HTTP/1.1\r\nHost: x\r\n\r\nput /x http/1.1\r\n\r\n`}, "HTTP PUT"},
		"tcp get with password": {Probe{Protocol: "tcp", Send: `GET / HTTP/1.1\r\nAuthorization: Basic eDp4\r\n\r\n`}, "Authorization"},
	} {
		why := tt.p.Unsafe()
		switch {
		case tt.want == "" && len(why) > 0:
			t.Errorf("%s: want safe, got %v", name, why)
		case tt.want != "" && !strings.Contains(strings.Join(why, "; "), tt.want):
			t.Errorf("%s: want a reason containing %q, got %v", name, tt.want, why)
		}
	}

	// verify reports the reasons as errors.
	src := strings.Replace(validRule, "confidence: high", "confidence: high\nprobes:\n  p:\n    protocol: http\n    request:\n      path: \"/ HTTP/1.1\\r\\n\\r\\nDELETE /admin\"", 1)
	r, err := Parse([]byte(src), "x.yml")
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, p := range Check(r) {
		if p.Severity == Error && strings.Contains(p.Msg, `probe "p": path`) {
			found = true
		}
	}
	if !found {
		t.Errorf("Check: no error for a path with a line break: %v", Check(r))
	}
}
