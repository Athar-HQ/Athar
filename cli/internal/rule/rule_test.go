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
