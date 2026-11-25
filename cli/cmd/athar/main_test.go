package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func runCLI(args ...string) (int, string, string) {
	var out, errOut bytes.Buffer
	code := run(args, &out, &errOut)
	return code, out.String(), errOut.String()
}

// TestRepositoryRules runs verify over the rules shipped in this repository.
func TestRepositoryRules(t *testing.T) {
	code, out, errOut := runCLI("verify", "-strict", "../../../rules")
	if code != exitOK {
		t.Fatalf("exit %d\n%s%s", code, out, errOut)
	}
}

func TestVerifyFailures(t *testing.T) {
	dir := t.TempDir()
	write := func(name, content string) {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	write("broken_test.yml", `
title: Broken test
id: 0ce69e91-baee-4475-81ee-4b8eca1a6c3b
status: experimental
target: { protocol: http }
detection:
  sel:
    http.title: Example
  condition: sel
identifies: { product: Example, category: web-server }
confidence: high
tests:
  - name: should match but does not
    expect: match
    response: { http.title: Other }
  - name: miss
    expect: no_match
    response: { http.title: Other }
`)
	write("bad_field.yml", `
title: Bad field
id: 0536c409-98ed-4d1d-8e07-7c80b39a4f53
status: experimental
target: { protocol: http }
detection:
  sel:
    http.titel: Example
  condition: sel
identifies: { product: Example, category: web-server }
confidence: high
`)
	write("notes.txt", "not a rule")

	code, out, _ := runCLI("verify", dir)
	if code != exitFindings {
		t.Errorf("exit %d, want %d\n%s", code, exitFindings, out)
	}
	for _, want := range []string{
		`test "should match but does not" failed: expected match`,
		`unknown field "http.titel"`,
		"2 rules, 2 failed; 1/2 tests passed",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("output misses %q:\n%s", want, out)
		}
	}
}

func TestVerifyStrict(t *testing.T) {
	dir := t.TempDir()
	rule := `
title: No tests
id: 0ce69e91-baee-4475-81ee-4b8eca1a6c3b
status: experimental
target: { protocol: http }
detection:
  sel:
    http.title: Example
  condition: sel
identifies: { product: Example, category: web-server }
confidence: high
`
	if err := os.WriteFile(filepath.Join(dir, "r.yml"), []byte(rule), 0o644); err != nil {
		t.Fatal(err)
	}
	if code, out, _ := runCLI("verify", dir); code != exitOK {
		t.Errorf("without -strict: exit %d\n%s", code, out)
	}
	if code, out, _ := runCLI("verify", "-strict", dir); code != exitFindings {
		t.Errorf("with -strict: exit %d\n%s", code, out)
	}
}

func TestUsage(t *testing.T) {
	for _, args := range [][]string{{}, {"nope"}, {"verify"}, {"verify", "/does/not/exist"}, {"scan"}} {
		if code, _, _ := runCLI(args...); code != exitUsage {
			t.Errorf("%v: exit %d, want %d", args, code, exitUsage)
		}
	}
	if code, out, _ := runCLI("version"); code != exitOK || !strings.HasPrefix(out, "athar ") {
		t.Errorf("version: exit %d, output %q", code, out)
	}
}
