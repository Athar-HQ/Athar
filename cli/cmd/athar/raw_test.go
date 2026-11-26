package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// athar verify reads a test's raw response with the scanner's code.
func TestVerifyRawResponse(t *testing.T) {
	const head = `
title: Raw tests
id: 0ce69e91-baee-4475-81ee-4b8eca1a6c3b
status: experimental
tags: [category.web-server]
target: { protocol: http }
detection:
  sel:
    http.title: 'Tom & Jerry'
    http.headers.server|contains: nginx
  condition: sel
identifies: { product: Example, category: web-server }
confidence: high
tests:
  - name: captured page
    expect: match
    raw: |
      HTTP/1.1 200 OK
      Server: nginx

      <html><head><title>Tom &amp; Jerry</title></head></html>
  - name: other server
    expect: no_match
    raw: "HTTP/1.1 200 OK\r\nServer: Apache\r\n\r\n<title>Tom &amp; Jerry</title>"
`
	dir := t.TempDir()
	good := filepath.Join(dir, "good.yml")
	if err := os.WriteFile(good, []byte(head), 0o644); err != nil {
		t.Fatal(err)
	}
	if code, out, errOut := runCLI("verify", "-strict", good); code != exitOK || !strings.Contains(out, "2/2 tests passed") {
		t.Fatalf("exit %d\n%s%s", code, out, errOut)
	}

	bad := filepath.Join(dir, "bad.yml")
	more := `  - name: title only in the text
    expect: match
    raw: |
      HTTP/1.1 200 OK
      Server: nginx

      <html><body>Tom &amp; Jerry</body></html>
  - name: not a response
    expect: match
    raw: '<title>Tom &amp; Jerry</title>'
`
	if err := os.WriteFile(bad, []byte(head+more), 0o644); err != nil {
		t.Fatal(err)
	}
	code, out, _ := runCLI("verify", bad)
	if code != exitFindings {
		t.Errorf("exit %d, want %d\n%s", code, exitFindings, out)
	}
	for _, want := range []string{
		`test "title only in the text" failed: expected match, got no_match`,
		`test "not a response" failed: raw: not an HTTP response`,
		"2/4 tests passed",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("output misses %q:\n%s", want, out)
		}
	}
}
