package probe

import (
	"bytes"
	"compress/gzip"
	"strings"
	"testing"
)

func TestHTTPFields(t *testing.T) {
	head := "HTTP/1.1 404 Not Found\r\nServer: nginx\r\nSet-Cookie: a=1\r\nSet-Cookie: b=2\r\n\r\n"
	page := "<html><head><title> Tom &amp;\n Jerry </title></head></html>\n"
	f, err := HTTPFields([]byte(head + page))
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]any{
		"http.status_code":    404,
		"http.title":          "Tom & Jerry",
		"http.body":           page, // no Content-Length: the body runs to the end
		"http.body.sha256":    sha256Hex([]byte(page)),
		"http.body.mmh3":      int(MMH3([]byte(page))),
		"http.headers.server": "nginx",
		"http.headers_raw":    head,
	}
	for k, v := range want {
		if f[k] != v {
			t.Errorf("%s = %#v, want %#v", k, f[k], v)
		}
	}
	if l, ok := f["http.headers.set-cookie"].([]any); !ok || len(l) != 2 {
		t.Errorf("http.headers.set-cookie = %#v, want two values", f["http.headers.set-cookie"])
	}
	for k := range f {
		if !strings.HasPrefix(k, "http.") && k != "service.protocol" {
			t.Errorf("unexpected field %s", k)
		}
	}
}

func TestHTTPFieldsBody(t *testing.T) {
	var gz bytes.Buffer
	zw := gzip.NewWriter(&gz)
	zw.Write([]byte("<title>Zipped</title>"))
	zw.Close()

	tests := []struct{ name, raw, body string }{
		{"Content-Length ends the body", "HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello\n", "hello"},
		{"chunked", "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n6\r\n world\r\n0\r\n\r\n", "hello world"},
		{"gzip", "HTTP/1.1 200 OK\r\nContent-Encoding: gzip\r\n\r\n" + gz.String(), "<title>Zipped</title>"},
		{"no body", "HTTP/1.1 204 No Content\r\nServer: x\r\n\r\n", ""},
	}
	for _, tc := range tests {
		f, err := HTTPFields([]byte(tc.raw))
		if err != nil {
			t.Errorf("%s: %v", tc.name, err)
			continue
		}
		if f["http.body"] != tc.body {
			t.Errorf("%s: http.body = %q, want %q", tc.name, f["http.body"], tc.body)
		}
	}
}

func TestHTTPFieldsBroken(t *testing.T) {
	for _, raw := range []string{
		"",
		"<html><title>no head</title></html>\n",
		"HTTP/1.1 200 OK\r\nServer: x\r\n", // the head never ends
		"HTTP/1.1 two hundred\r\n\r\n",
	} {
		if f, err := HTTPFields([]byte(raw)); err == nil {
			t.Errorf("%q: no error, fields %v", raw, f)
		}
	}
}
