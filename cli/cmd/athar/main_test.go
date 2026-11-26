package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/Athar-HQ/Athar/cli/internal/convert"
	"github.com/Athar-HQ/Athar/cli/internal/rule"
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

// "--" ends the flags: everything after it is a positional argument.
func TestDoubleDash(t *testing.T) {
	fs := flag.NewFlagSet("test", flag.ContinueOnError)
	jsonOut, rules := fs.Bool("json", false, ""), fs.String("r", "", "")
	pos, err := parseFlags(fs, []string{"a", "-r", "rules", "--", "host", "-json", "--", "b"})
	if err != nil || *jsonOut || *rules != "rules" || strings.Join(pos, " ") != "a host -json -- b" {
		t.Errorf("positional %q, json %v, r %q, err %v", pos, *jsonOut, *rules, err)
	}

	// What follows "--" is a path or a target, so these fail: no file is
	// named like a flag, and the scan has no -r.
	for _, args := range [][]string{
		{"verify", "--", "../../../rules", "-q"},
		{"convert", "--", "../../../rules", "-json"},
		{"scan", "--", "127.0.0.1:1", "-r", "../../../rules"},
	} {
		if code, _, errOut := runCLI(args...); code != exitUsage {
			t.Errorf("%v: exit %d, want %d\n%s", args, code, exitUsage, errOut)
		}
	}
}

// A file given twice, also through its folder, another spelling or a
// symlink, is loaded once. Two files with one id are still an error.
func TestSameFileTwice(t *testing.T) {
	dir := t.TempDir()
	a := filepath.Join(dir, "a.yml")
	if err := os.WriteFile(a, []byte(convertFixture), 0o644); err != nil {
		t.Fatal(err)
	}
	spellings := []string{a, dir + "/./a.yml"}
	link := filepath.Join(t.TempDir(), "link")
	if err := os.Symlink(dir, link); err == nil {
		spellings = append(spellings, filepath.Join(link, "a.yml"))
	}
	for _, same := range spellings {
		if code, out, errOut := runCLI("verify", dir, same); code != exitOK || !strings.Contains(out, "\n1 rule, ") {
			t.Errorf("verify %s %s: exit %d\n%s%s", dir, same, code, out, errOut)
		}
		if code, _, errOut := runCLI("scan", "-r", dir, "-r", same, "127.0.0.1:1"); code != exitOK {
			t.Errorf("scan -r %s -r %s: exit %d\n%s", dir, same, code, errOut)
		}
		if code, out, errOut := runCLI("convert", "-t", "fofa", "-json", dir, same); code != exitOK || strings.Count(out, "\n") != 1 {
			t.Errorf("convert %s %s: exit %d\n%s%s", dir, same, code, out, errOut)
		}
	}

	if err := os.WriteFile(filepath.Join(dir, "b.yml"), []byte(convertFixture), 0o644); err != nil {
		t.Fatal(err)
	}
	if code, out, _ := runCLI("verify", dir); code != exitFindings || !strings.Contains(out, "is already used by") {
		t.Errorf("two files with one id: exit %d\n%s", code, out)
	}
}

func TestScanCommand(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`<title>NKW — Autonomous Penetration Testing Console</title><a href="/function/tasks">`))
	}))
	defer srv.Close()
	target := strings.TrimPrefix(srv.URL, "http://")

	// Readable lines by default, without colors when not on a terminal.
	code, out, errOut := runCLI("scan", target, "-r", "../../../rules", "-timeout", "2s", "-connect-timeout", "1s", "-v")
	if code != exitOK {
		t.Fatalf("exit %d\n%s", code, errOut)
	}
	wantLine := target + "  Agentic Offensive Framework - ARTEX rebrands  [offensive-tool] [high]  brand=NKW  by Gameel Ali (@MalGamy12)\n"
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
		{"scan", "-r", "../../../rules", "-connect-timeout", "0", "127.0.0.1"},
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

func TestConvertNuclei(t *testing.T) {
	dir := t.TempDir()
	fixture := filepath.Join(dir, "family.yml")
	if err := os.WriteFile(fixture, []byte(convertFixture), 0o644); err != nil {
		t.Fatal(err)
	}

	// Alone, -t nuclei prints the template itself, ready for a file.
	code, out, errOut := runCLI("convert", "-t", "nuclei", fixture)
	if code != exitOK {
		t.Fatalf("exit %d\n%s", code, errOut)
	}
	if !strings.HasPrefix(out, "# Converted by athar convert from ") || !strings.Contains(out, "\nid: athar-family\n") {
		t.Errorf("stdout is not the template:\n%s", out)
	}

	// With -o, each template goes to <id>.yaml and the line names the file.
	tdir := filepath.Join(dir, "templates")
	code, out, errOut = runCLI("convert", "-t", "fofa,nuclei", "-o", tdir, "-no-color", fixture)
	if code != exitOK {
		t.Fatalf("-o: exit %d\n%s", code, errOut)
	}
	file := filepath.Join(tdir, "athar-family.yaml")
	if !strings.Contains(out, "  nuclei   exact        "+file+"\n") {
		t.Errorf("-o output:\n%s", out)
	}
	if b, err := os.ReadFile(file); err != nil || !strings.Contains(string(b), "id: athar-family") {
		t.Errorf("template file: %v\n%s", err, b)
	}

	// -json carries the template, or the file with -o.
	code, out, _ = runCLI("convert", "-t", "nuclei", "-json", fixture)
	var res struct {
		Engine, Template, Fidelity string
		TemplateID                 string `json:"template_id"`
	}
	if code != exitOK || json.Unmarshal([]byte(out), &res) != nil || res.Engine != "nuclei" ||
		res.TemplateID != "athar-family" || !strings.Contains(res.Template, "id: athar-family") {
		t.Errorf("-json: exit %d, %+v\n%s", code, res, out)
	}

	if code, _, _ := runCLI("convert", "-t", "fofa", "-o", tdir, fixture); code != exitUsage {
		t.Errorf("-o without nuclei: exit %d, want %d", code, exitUsage)
	}
}

func TestConvertNSE(t *testing.T) {
	dir := t.TempDir()
	fixture := filepath.Join(dir, "family.yml")
	if err := os.WriteFile(fixture, []byte(convertFixture), 0o644); err != nil {
		t.Fatal(err)
	}

	// Alone, -t nse prints the rule's data file.
	code, out, errOut := runCLI("convert", "-t", "nse", fixture)
	if code != exitOK {
		t.Fatalf("exit %d\n%s", code, errOut)
	}
	if !strings.HasPrefix(out, "-- Athar rule data for athar.nse") || !strings.Contains(out, "\nreturn {\n  nse = 1,\n") {
		t.Errorf("stdout is not the data file:\n%s", out)
	}

	// With -o, the script goes to the folder and the data file under
	// athar-rules.
	odir := filepath.Join(dir, "nse")
	code, out, errOut = runCLI("convert", "-t", "nse", "-o", odir, "-no-color", fixture)
	if code != exitOK {
		t.Fatalf("-o: exit %d\n%s", code, errOut)
	}
	file := filepath.Join(odir, "athar-rules", "family.lua")
	if !strings.Contains(out, "  nse      exact        "+file+"\n") {
		t.Errorf("-o output:\n%s", out)
	}
	if b, err := os.ReadFile(filepath.Join(odir, "athar.nse")); err != nil || string(b) != convert.NSEScript {
		t.Errorf("athar.nse not written: %v", err)
	}
	if b, err := os.ReadFile(file); err != nil || !strings.Contains(string(b), "return {") {
		t.Errorf("data file: %v\n%s", err, b)
	}

	// -json carries the data file.
	code, out, _ = runCLI("convert", "-t", "nse", "-json", fixture)
	var res struct {
		Engine, Template string
		TemplateID       string `json:"template_id"`
	}
	if code != exitOK || json.Unmarshal([]byte(out), &res) != nil || res.Engine != "nse" ||
		res.TemplateID != "family" || !strings.Contains(res.Template, "return {") {
		t.Errorf("-json: exit %d, %+v\n%s", code, res, out)
	}

	// Both scanners: one document each, separated by ---, a comment in Lua.
	code, out, _ = runCLI("convert", "-t", "nuclei,nse", fixture)
	if code != exitOK || !strings.Contains(out, "\n---\n-- Athar rule data for athar.nse") {
		t.Errorf("nuclei and nse: exit %d\n%s", code, out)
	}
}

// The rule in the README's "A rule" section is the first one people read.
// It is a shortened version of a real rule, so it must pass verify -strict,
// and every value it matches on must still be in the real rule it links to.
func TestReadmeRuleExample(t *testing.T) {
	readme, err := os.ReadFile("../../../README.md")
	if err != nil {
		t.Fatal(err)
	}
	text := string(readme)
	section := strings.Index(text, "## A rule\n")
	if section < 0 {
		t.Fatal(`README has no "## A rule" section`)
	}
	text = text[section:]
	if next := strings.Index(text[1:], "\n## "); next >= 0 {
		text = text[:next+1]
	}
	start := strings.Index(text, "```yaml\n")
	if start < 0 {
		t.Fatal(`no yaml block in the "A rule" section`)
	}
	end := strings.Index(text[start+8:], "```")
	if end < 0 {
		t.Fatal(`unterminated yaml block in the "A rule" section`)
	}
	example := text[start+8 : start+8+end]

	path := filepath.Join(t.TempDir(), "readme-example.yml")
	if err := os.WriteFile(path, []byte(example), 0o644); err != nil {
		t.Fatal(err)
	}
	if code, out, errOut := runCLI("verify", "-strict", path); code != exitOK {
		t.Fatalf("README rule example fails verify -strict:\n%s%s", out, errOut)
	}

	link := regexp.MustCompile(`\]\((rules/[^)]+\.yml)\)`).FindStringSubmatch(text)
	if link == nil {
		t.Fatal(`the "A rule" section links to no rule in rules/`)
	}
	real, err := rule.Load("../../../" + link[1])
	if err != nil {
		t.Fatal(err)
	}
	ex, err := rule.Parse([]byte(example), "README.md")
	if err != nil {
		t.Fatal(err)
	}
	have := map[string]bool{}
	for _, v := range detectionValues(real.Detection) {
		have[v] = true
	}
	for _, v := range detectionValues(ex.Detection) {
		if !have[v] {
			t.Errorf("README rule example matches on %q, which %s no longer has; update the \"A rule\" section", v, link[1])
		}
	}
}

// detectionValues returns the values a detection block matches on.
func detectionValues(det map[string]any) []string {
	var out []string
	var walk func(any)
	walk = func(v any) {
		switch x := v.(type) {
		case map[string]any:
			for k, e := range x {
				if k != "condition" && k != "probe" {
					walk(e)
				}
			}
		case []any:
			for _, e := range x {
				walk(e)
			}
		case nil:
		default:
			out = append(out, fmt.Sprint(x))
		}
	}
	walk(det)
	return out
}
