package output

import (
	"bytes"
	"encoding/json"
	"os"
	"strings"
	"testing"

	"github.com/Athar-HQ/Athar/cli/internal/color"
)

var argos = Record{
	Target:     "144.202.110.94:443",
	TLS:        true,
	Rule:       "0ce69e91-baee-4475-81ee-4b8eca1a6c3b",
	Title:      "Agentic Offensive Framework - ARTEX family",
	Author:     "Gameel Ali (@MalGamy12)",
	Family:     "artex",
	Category:   "offensive-tool",
	Extracted:  map[string]string{"brand": "ARGOS", "version": "1.2"},
	Confidence: "high",
	Matched:    []string{"selection_route", "selection_title"},
	Probes:     []string{"default"},
	Observed:   "2026-11-25T08:11:37Z",
}

func TestText(t *testing.T) {
	var buf bytes.Buffer
	if err := NewText(&buf, color.New(false)).Write(argos); err != nil {
		t.Fatal(err)
	}
	want := "144.202.110.94:443 (tls)  Agentic Offensive Framework - ARTEX family  [offensive-tool] [high]  brand=ARGOS version=1.2  by Gameel Ali (@MalGamy12)\n"
	if buf.String() != want {
		t.Errorf("got  %q\nwant %q", buf.String(), want)
	}

	r := argos
	r.Target, r.IP, r.TLS, r.Extracted, r.Confidence, r.Author = "panel.example:8443", "192.0.2.7", false, nil, "low", ""
	buf.Reset()
	NewText(&buf, color.New(false)).Write(r)
	if want := "panel.example:8443 (192.0.2.7)  Agentic Offensive Framework - ARTEX family  [offensive-tool] [low]\n"; buf.String() != want {
		t.Errorf("got  %q\nwant %q", buf.String(), want)
	}
}

// Extracted values come from the scanned service. In readable output their
// control characters must not reach the terminal; JSON keeps the value.
func TestTextEscapesExtracted(t *testing.T) {
	r := argos
	r.Author = ""
	r.Extracted = map[string]string{
		"brand":   "\x1b[2J\x1b]0;owned\aFAKE",
		"c0":      "a\nb\rc\td\x00e\x7f",
		"c1":      "\u009b31mred\u0085x\xff\x9b",
		"bidi":    "\u202eevil\u202a\u2066x\u2069\u2028y",
		"chinese": "海盗船-内部渗透框架",
		"korean":  "자율 침투 v2 · café",
	}
	var buf bytes.Buffer
	if err := NewText(&buf, color.New(false)).Write(r); err != nil {
		t.Fatal(err)
	}
	want := `144.202.110.94:443 (tls)  Agentic Offensive Framework - ARTEX family  [offensive-tool] [high]  ` +
		`bidi=\u202eevil\u202a\u2066x\u2069\u2028y brand=\x1b[2J\x1b]0;owned\x07FAKE c0=a\nb\rc\td\x00e\x7f ` +
		`c1=\u009b31mred\u0085x\xff\x9b chinese=海盗船-内部渗透框架 korean=자율 침투 v2 · café` + "\n"
	if buf.String() != want {
		t.Errorf("got  %q\nwant %q", buf.String(), want)
	}

	buf.Reset()
	NewText(&buf, color.New(true)).Write(r)
	if out := buf.String(); !strings.Contains(out, "\x1b[1m\x1b[33m\\x1b[2J\\x1b]0;owned\\x07FAKE\x1b[0m\x1b[0m") || strings.Count(out, "\n") != 1 {
		t.Errorf("colored line = %q", out)
	}

	buf.Reset()
	r.Extracted = map[string]string{"brand": "\x1b[2J\u202eA\nB"}
	NewJSON(&buf).Write(r)
	var back Record
	if err := json.Unmarshal(buf.Bytes(), &back); err != nil {
		t.Fatal(err)
	}
	if back.Extracted["brand"] != r.Extracted["brand"] || strings.Count(buf.String(), "\n") != 1 || strings.Contains(buf.String(), "\x1b") {
		t.Errorf("JSON line = %q", buf.String())
	}
}

func TestTextColors(t *testing.T) {
	var buf bytes.Buffer
	NewText(&buf, color.New(true)).Write(argos)
	out := buf.String()
	for _, want := range []string{
		"\x1b[1m\x1b[36m144.202.110.94:443\x1b[0m\x1b[0m", // target: bold cyan
		"\x1b[32m[high]\x1b[0m",                           // confidence: green
		"\x1b[1m\x1b[33mARGOS\x1b[0m\x1b[0m",              // extracted value: bold yellow
	} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q in %q", want, out)
		}
	}
}

func TestJSON(t *testing.T) {
	var buf bytes.Buffer
	NewJSON(&buf).Write(argos)
	var back Record
	if err := json.Unmarshal(buf.Bytes(), &back); err != nil {
		t.Fatal(err)
	}
	if back.Extracted["brand"] != "ARGOS" || back.Author != "Gameel Ali (@MalGamy12)" || !strings.HasSuffix(buf.String(), "}\n") {
		t.Errorf("JSON line = %q", buf.String())
	}
}

func TestColorFor(t *testing.T) {
	if color.For(&bytes.Buffer{}, false).On() {
		t.Error("colors on for a buffer")
	}
	// A regular file is not a terminal.
	f, err := os.CreateTemp(t.TempDir(), "out")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if color.For(f, false).On() {
		t.Error("colors on for a regular file")
	}
	if got := color.New(false).Red("x"); got != "x" {
		t.Errorf("palette off changed the string: %q", got)
	}
}
