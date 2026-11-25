package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
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

// Flags may follow the positional arguments, as in Nmap.
func TestInterleavedFlags(t *testing.T) {
	if code, out, errOut := runCLI("verify", "../../../rules", "-strict", "-q"); code != exitOK {
		t.Errorf("exit %d\n%s%s", code, out, errOut)
	}
}

func TestScanCommand(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`<title>NKW — Autonomous Penetration Testing Console</title><a href="/function/tasks">`))
	}))
	defer srv.Close()
	target := strings.TrimPrefix(srv.URL, "http://")

	// Readable lines by default, without colors when not on a terminal.
	code, out, errOut := runCLI("scan", target, "-r", "../../../rules", "-timeout", "2s", "-v")
	if code != exitOK {
		t.Fatalf("exit %d\n%s", code, errOut)
	}
	wantLine := target + "  Agentic Offensive Framework - ARTEX family  [offensive-tool] [high]  brand=NKW\n"
	if out != wantLine {
		t.Errorf("text output:\n got %q\nwant %q", out, wantLine)
	}
	if strings.Contains(out+errOut, "\x1b[") {
		t.Error("colors written to a non-terminal")
	}
	for _, want := range []string{"open " + target + " http 200", "1 host, 1 check, 1 open, 1 match"} {
		if !strings.Contains(errOut, want) {
			t.Errorf("stderr misses %q:\n%s", want, errOut)
		}
	}

	// JSON lines with -json.
	code, out, errOut = runCLI("scan", target, "-r", "../../../rules", "-json")
	if code != exitOK {
		t.Fatalf("-json: exit %d\n%s", code, errOut)
	}
	var rec struct {
		Target    string
		Extracted map[string]string
	}
	if err := json.Unmarshal([]byte(out), &rec); err != nil {
		t.Fatalf("-json output %q: %v", out, err)
	}
	if rec.Target != target || rec.Extracted["brand"] != "NKW" {
		t.Errorf("record = %+v", rec)
	}

	// Results to a file, targets from a file.
	dir := t.TempDir()
	list := filepath.Join(dir, "targets.txt")
	os.WriteFile(list, []byte("# comment\n\n"+target+"\n"), 0o644)
	results := filepath.Join(dir, "out.jsonl")
	if code, out, errOut := runCLI("scan", "-r", "../../../rules", "-iL", list, "-json", "-o", results); code != exitOK || out != "" {
		t.Fatalf("exit %d, stdout %q\n%s", code, out, errOut)
	}
	if b, _ := os.ReadFile(results); !bytes.Contains(b, []byte(`"brand":"NKW"`)) {
		t.Errorf("results file = %q", b)
	}
}

func TestScanUsageErrors(t *testing.T) {
	for _, args := range [][]string{
		{"scan", "127.0.0.1"},            // no rules
		{"scan", "-r", "../../../rules"}, // no targets
		{"scan", "-r", "../../../rules", "-p", "0", "127.0.0.1"},
		{"scan", "-r", "../../../rules", "-rate", "-1", "127.0.0.1"},
		{"scan", "-r", "../../../rules", "10.0.0.0/8"}, // range too large
		{"scan", "-r", "../../../rules", "http://example.org"},
		{"scan", "-r", "/does/not/exist", "127.0.0.1"},
	} {
		if code, _, errOut := runCLI(args...); code != exitUsage {
			t.Errorf("%v: exit %d, want %d\n%s", args, code, exitUsage, errOut)
		}
	}

	// Invalid rules stop the scan before any packet is sent.
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "bad.yml"), []byte("title: x\n"), 0o644)
	code, _, errOut := runCLI("scan", "-r", dir, "127.0.0.1")
	if code != exitUsage || !strings.Contains(errOut, "athar verify") {
		t.Errorf("invalid rule: exit %d\n%s", code, errOut)
	}
}

// convertFixture is the family rule from spec section 10, kept here so
// edits to the live rules don't change the expected output.
const convertFixture = `
title: Agentic Offensive Framework - ARTEX family
id: 0ce69e91-baee-4475-81ee-4b8eca1a6c3b
status: experimental
target: { protocol: http }
detection:
  selection_title:
    http.title|contains: 'Autonomous Penetration Testing Console'
  selection_route:
    http.body|contains: '/function/tasks'
  condition: selection_title and selection_route
identifies: { family: artex, category: offensive-tool }
confidence: high
`

func TestConvertCommand(t *testing.T) {
	fixture := filepath.Join(t.TempDir(), "family.yml")
	if err := os.WriteFile(fixture, []byte(convertFixture), 0o644); err != nil {
		t.Fatal(err)
	}
	code, out, errOut := runCLI("convert", "-t", "fofa,shodan", fixture)
	if code != exitOK {
		t.Fatalf("exit %d\n%s", code, errOut)
	}
	want := "Agentic Offensive Framework - ARTEX family  " + fixture + "\n" +
		"  fofa     exact        title=\"Autonomous Penetration Testing Console\" && body=\"/function/tasks\"\n" +
		"  shodan   approximate  http.title:\"Autonomous Penetration Testing Console\" http.html:\"/function/tasks\"\n" +
		"                        note: shodan does not index all of a large body; a body condition can miss hosts the scanner finds\n"
	if out != want {
		t.Errorf("text output:\n got %q\nwant %q", out, want)
	}

	code, out, _ = runCLI("convert", "../../../rules", "-json", "-t", "censys")
	if code != exitOK {
		t.Fatalf("-json: exit %d", code)
	}
	lines := strings.Split(strings.TrimSpace(out), "\n")
	if len(lines) < 3 {
		t.Fatalf("want one line per rule, got %q", out)
	}
	var res struct {
		Rule, Engine, Query, Fidelity string
		Notes                         []string
	}
	for _, l := range lines {
		if err := json.Unmarshal([]byte(l), &res); err != nil {
			t.Fatalf("%q: %v", l, err)
		}
		if res.Engine != "censys" || res.Rule == "" || res.Fidelity == "" {
			t.Errorf("record = %+v", res)
		}
	}

	for _, args := range [][]string{
		{"convert"},
		{"convert", "-t", "bing", "../../../rules"},
		{"convert", "-t", ",", "../../../rules"},
		{"convert", "/does/not/exist"},
	} {
		if code, _, _ := runCLI(args...); code != exitUsage {
			t.Errorf("%v: exit %d, want %d", args, code, exitUsage)
		}
	}
}
