package rule

import (
	"strings"
	"testing"
)

func TestRawResponse(t *testing.T) {
	tests := []struct{ name, raw, want string }{
		{"LF head", "HTTP/1.1 200 OK\nServer: x\n\n<p>a\nb</p>\n", "HTTP/1.1 200 OK\r\nServer: x\r\n\r\n<p>a\nb</p>\n"},
		{"LF head, CR in the body", "HTTP/1.1 200 OK\n\na\r\nb", "HTTP/1.1 200 OK\r\n\r\na\r\nb"},
		{"CRLF head", "HTTP/1.1 200 OK\r\nServer: x\r\n\r\na\nb\n", "HTTP/1.1 200 OK\r\nServer: x\r\n\r\na\nb\n"},
		{"head with a CR is taken as written", "HTTP/1.1 200 OK\r\nServer: x\n\nbody", "HTTP/1.1 200 OK\r\nServer: x\n\nbody"},
		{"LF head without the empty line", "HTTP/1.1 204 No Content\nServer: x\n", "HTTP/1.1 204 No Content\r\nServer: x\r\n\r\n"},
		{"LF head without the last line end", "HTTP/1.1 204 No Content\nServer: x", "HTTP/1.1 204 No Content\r\nServer: x\r\n\r\n"},
		{"CRLF head without the empty line", "HTTP/1.1 204 No Content\r\nServer: x\r\n", "HTTP/1.1 204 No Content\r\nServer: x\r\n"},
		{"empty", "", ""},
	}
	for _, tc := range tests {
		if got := string(RawResponse(tc.raw)); got != tc.want {
			t.Errorf("%s: got %q, want %q", tc.name, got, tc.want)
		}
	}
}

// A block scalar, a double-quoted string with escapes and !!binary all end
// up as the same bytes.
func TestRawInYAML(t *testing.T) {
	forms := []string{
		"    raw: |-\n      HTTP/1.1 200 OK\n      Server: x\n\n      <title>Example</title>",
		`    raw: "HTTP/1.1 200 OK\r\nServer: x\r\n\r\n<title>Example</title>"`,
		"    raw: !!binary SFRUUC8xLjEgMjAwIE9LDQpTZXJ2ZXI6IHgNCg0KPHRpdGxlPkV4YW1wbGU8L3RpdGxlPg==",
	}
	for _, form := range forms {
		src := strings.Replace(validRule, "    response: { http.title: Example }", form, 1)
		r, err := Parse([]byte(src), "raw.yml")
		if err != nil {
			t.Fatal(err)
		}
		if p := Check(r); len(p) != 0 {
			t.Errorf("%s: unexpected problems: %v", form, p)
		}
		want := "HTTP/1.1 200 OK\r\nServer: x\r\n\r\n<title>Example</title>"
		if got := string(RawResponse(r.Tests[0].Raw)); got != want {
			t.Errorf("%s: got %q, want %q", form, got, want)
		}
	}

	// Bytes that are not UTF-8 need !!binary: a "\xff" escape is U+00FF.
	for form, want := range map[string]string{
		`    raw: !!binary SFRUUC8xLjEgMjAwIE9LDQoNCv8A`: "HTTP/1.1 200 OK\r\n\r\n\xff\x00",
		`    raw: "HTTP/1.1 200 OK\r\n\r\n\xff\x00"`:     "HTTP/1.1 200 OK\r\n\r\n\u00ff\x00",
	} {
		src := strings.Replace(validRule, "    response: { http.title: Example }", form, 1)
		r, err := Parse([]byte(src), "raw.yml")
		if err != nil {
			t.Fatal(err)
		}
		if got := string(RawResponse(r.Tests[0].Raw)); got != want {
			t.Errorf("%s: got %q, want %q", form, got, want)
		}
	}
}

func TestCheckRaw(t *testing.T) {
	probes := "confidence: high\nprobes:\n  css: { protocol: http, request: { path: /a.css } }\n  hello: { protocol: tcp }"
	tests := []struct{ with, want string }{
		{"", "missing response"},
		{"    raw: ''", "missing response"},
		{"    probes: { css: { raw: [200] } }", `probe "css": raw must be a string`},
		{"    probes: { hello: { raw: \"HTTP/1.1 200 OK\\n\" } }", `probe "hello": raw needs an http probe`},
		{"    probes: { css: { raw: \"HTTP/1.1 200 OK\\n\" } }", ""},
	}
	for _, tc := range tests {
		src := strings.Replace(validRule, "confidence: high", probes, 1)
		src = strings.Replace(src, "    response: { http.title: Example }", tc.with, 1)
		r, err := Parse([]byte(src), "raw.yml")
		if err != nil {
			t.Fatal(err)
		}
		p := Check(r)
		if tc.want == "" {
			if len(p) != 0 {
				t.Errorf("%q: unexpected problems: %v", tc.with, p)
			}
			continue
		}
		if len(p) != 1 || p[0].Severity != Error || !strings.Contains(p[0].Msg, tc.want) {
			t.Errorf("%q: problems = %v, want one error with %q", tc.with, p, tc.want)
		}
	}
}
