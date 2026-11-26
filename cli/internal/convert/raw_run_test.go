package convert

import (
	"context"
	"net"
	"net/url"
	"strconv"
	"testing"
	"time"

	"github.com/Athar-HQ/Athar/cli/internal/probe"
	"github.com/Athar-HQ/Athar/cli/internal/rule"
)

// The Nuclei and Nmap run tests serve a test's raw response as it is, so the
// scanner reads from the server what athar verify derives from the text.
func TestServeTestRaw(t *testing.T) {
	r, err := rule.Parse([]byte(`
title: Raw
probes:
  css: { protocol: http, request: { path: /app.css } }
tests:
  - name: raw
    raw: |
      HTTP/1.1 200 OK
      Server: Example
      Content-Type: text/html

      <html><head><title>Tom &amp; Jerry</title></head></html>
    probes:
      css:
        raw: "HTTP/1.1 200 OK\r\nContent-Type: text/css\r\n\r\nabc"
  - name: a field on top of raw can't be served
    raw: "HTTP/1.1 200 OK\r\n\r\n"
    response: { http.title: Other }
`), "raw.yml")
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := serveTest(t, r, r.Tests[1]); ok {
		t.Error("a test with an http field on top of raw was served")
	}
	srv, ok := serveTest(t, r, r.Tests[0])
	if !ok {
		t.Fatal("a raw test was not served")
	}
	u, _ := url.Parse(srv)
	host, portStr, _ := net.SplitHostPort(u.Host)
	port, _ := strconv.Atoi(portStr)
	css := r.Probes["css"]
	p := &probe.Prober{Timeout: 5 * time.Second, Needs: probe.Needs{HTTP: true},
		Custom: []probe.CustomProbe{{Key: "css", Probe: css}}}
	svc := p.Probe(context.Background(), host, port)
	if svc == nil {
		t.Fatal("no service")
	}
	want, err := probe.HTTPFields(rule.RawResponse(r.Tests[0].Raw))
	if err != nil {
		t.Fatal(err)
	}
	for k, v := range want {
		if svc.Fields[k] != v {
			t.Errorf("%s = %#v from the server, %#v from the text", k, svc.Fields[k], v)
		}
	}
	if got := svc.Custom["css"]["http.body"]; got != "abc" {
		t.Errorf("custom probe body = %#v, want \"abc\"", got)
	}
}
