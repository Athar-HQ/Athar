package convert

import (
	"html"
	"regexp"
	"strconv"
	"strings"
	"testing"

	"github.com/Athar-HQ/Athar/cli/internal/rule"
)

func nseFor(t *testing.T, detection string) Result {
	t.Helper()
	return nseRule(t, ruleFrom(t, detection))
}

func nseRule(t *testing.T, r *rule.Rule) Result {
	t.Helper()
	res, err := Convert(r, "nse")
	if err != nil {
		t.Fatal(err)
	}
	return res
}

func wantData(t *testing.T, res Result, parts ...string) {
	t.Helper()
	for _, p := range parts {
		if !strings.Contains(res.Template, p) {
			t.Errorf("data lacks %q:\n%s", p, res.Template)
		}
	}
}

func TestNSEFamily(t *testing.T) {
	res := nseFor(t, specFamily)
	if res.Fidelity != Exact || res.TemplateID != "t" {
		t.Errorf("fidelity %s, id %q", res.Fidelity, res.TemplateID)
	}
	wantData(t, res,
		"-- Fidelity: exact\n",
		"return {\n  nse = 1,\n",
		// Without target.protocol, athar scan also waits for a banner.
		`needs = {banner = true, tls = true, http = true}`,
		`{f = "http.title", m = "contains", v = "autonomous penetration testing console"}`,
		`{f = "http.body", m = "contains", v = "/function/tasks"}`,
		// s and k also match ſ and the Kelvin sign.
		"fold = {[\"ſ\"] = \"s\", [\"\u212a\"] = \"k\"}",
		"condition = {\"and\",\n",
	)
}

func TestNSEFaviconAndNegation(t *testing.T) {
	res := nseFor(t, `
selection_title:
  http.title|contains: 'Console'
filter_icon:
  http.favicon.mmh3: -576220750
filter_brand:
  http.title|startswith|cased: 'ARTEX'
condition: selection_title and not 1 of filter_*
`)
	if res.Fidelity != Exact {
		t.Errorf("fidelity %s, want exact: the script fetches favicons as athar scan does", res.Fidelity)
	}
	wantData(t, res,
		`needs = {banner = true, tls = true, http = true, favicon = true}`,
		`{f = "http.favicon.mmh3", m = "eq", v = "-576220750", n = true}`,
		`{f = "http.title", m = "startswith", v = "ARTEX", c = true, n = true}`,
	)
}

func TestNSERegexAndExtract(t *testing.T) {
	r := ruleFrom(t, `
selection:
  tls.cert.san|re: '(?i)^antifox\..+\.nip\.io$'
  http.title: 'Acme * Console'
condition: selection
`)
	r.Extract = map[string]rule.Extract{"brand": {Field: "http.title", Regex: `^(?P<brand>\w+) `}}
	res := nseRule(t, r)
	if res.Fidelity != Exact {
		t.Errorf("fidelity %s, notes %q", res.Fidelity, res.Notes)
	}
	wantData(t, res,
		`{f = "http.title", m = "re", r = 1}`,
		`{f = "tls.cert.san", m = "re", r = 2}`,
		`{name = "brand", f = "http.title", r = 3, g = 1}`,
		"re = {\n    {s = ",
		", a = true, i = {{5}, ",
	)
	// The wildcard compiles to the evaluator's pattern, (?is)^Acme .* Console$:
	// the A of Acme folds, so its instruction lists both cases.
	if !strings.Contains(res.Template, "{7, ") || !strings.Contains(res.Template, ", 65, 65, 97, 97}") {
		t.Errorf("no folded rune ranges for the wildcard:\n%s", res.Template)
	}
}

func TestNSEValues(t *testing.T) {
	res := nseFor(t, `
selection:
  service.banner|hex|startswith: '00 01 ff'
  http.status_code|gte: 400
  http.headers.x-api: null
  http.body|contains|cased: "say \"hi\"\t\\"
keywords:
  - 'K'
condition: selection and keywords
`)
	wantData(t, res,
		`{f = "service.banner", m = "startswith", v = "\x00\x01\xff", c = true}`,
		`{f = "http.status_code", m = "num", o = "gte", x = 400}`,
		`{f = "http.headers.x-api", m = "exists", x = false}`,
		`{f = "http.body", m = "contains", v = "say \"hi\"\t\\", c = true}`,
		`{k = true, m = "contains", v = "k"}`,
		"fold = {[\"\u212a\"] = \"k\"}",
		`needs = {banner = true, tls = true, http = true}`,
	)
}

func TestNSEDropsWhatItCannotRead(t *testing.T) {
	res := nseFor(t, `
selection:
  http.title|contains: 'Console'
  tls.jarm: '2ad2ad16d2ad2ad00042d42d00000069d641f34fe76acdc05c40262f8815e5'
condition: selection
`)
	if res.Fidelity != Superset || len(res.Notes) == 0 || !strings.Contains(res.Notes[0], "tls.jarm") {
		t.Errorf("fidelity %s, notes %q", res.Fidelity, res.Notes)
	}
	res = nseFor(t, `
selection:
  tls.cert.self_signed: true
condition: selection
`)
	if res.Fidelity != Unsupported || res.Template != "" {
		t.Errorf("self_signed only: fidelity %s, template %q", res.Fidelity, res.Template)
	}
	// Banners convert, unlike for Nuclei.
	if res := nseFor(t, "selection:\n  ssh.banner|startswith: 'SSH-2.0-'\ncondition: selection\n"); res.Fidelity != Exact {
		t.Errorf("ssh.banner: fidelity %s", res.Fidelity)
	}
	r := ruleFrom(t, "selection:\n  service.banner|contains: 'x'\ncondition: selection\n")
	r.Target.Transport = "udp"
	if res := nseRule(t, r); res.Fidelity != Unsupported || res.Template != "" {
		t.Errorf("udp: fidelity %s", res.Fidelity)
	}
}

func TestNSECustomProbe(t *testing.T) {
	res := nseFor(t, `
selection:
  probe: api
  http.body|contains: '"status":"ok"'
condition: selection
`)
	if res.Fidelity != Exact {
		t.Errorf("fidelity %s", res.Fidelity)
	}
	wantData(t, res,
		`["api"] = {key = "http||/api|\"\"", proto = "http", method = "GET", path = "/api"}`,
		`{p = "api", f = "http.body", m = "contains", v = "\"status\":\"ok\""}`,
		"-- Note: declares 1 custom probe, sent only with --script-args athar.probes (athar scan: -probes)\n",
	)
}

func TestNSEScriptHeader(t *testing.T) {
	for _, want := range []string{"SPDX-License-Identifier: MIT", `license = "MIT"`, "local FORMAT = " + strconv.Itoa(nseFormat) + "\n"} {
		if !strings.Contains(NSEScript, want) {
			t.Errorf("athar.nse lacks %q", want)
		}
	}
}

// The entity table in athar.nse must decode as Go's html package does,
// which athar scan uses for titles and attributes.
func TestNSEEntities(t *testing.T) {
	list := NSEScript[strings.Index(NSEScript, "local ENTITY_LIST = [[")+len("local ENTITY_LIST = [["):]
	list = list[:strings.Index(list, "]]")]
	entries := regexp.MustCompile(`([A-Za-z][A-Za-z0-9]*)(\*?)\s+(\d+)`).FindAllStringSubmatch(list, -1)
	if len(entries) < 250 {
		t.Fatalf("only %d entities", len(entries))
	}
	for _, e := range entries {
		cp, _ := strconv.Atoi(e[3])
		want := string(rune(cp))
		if got := html.UnescapeString("&" + e[1] + ";"); got != want {
			t.Errorf("&%s; is %q in Go, %q in athar.nse", e[1], got, want)
		}
		legacy := html.UnescapeString("&"+e[1]) == want
		if legacy != (e[2] == "*") {
			t.Errorf("&%s without semicolon: Go decodes it: %v; athar.nse: %v", e[1], legacy, e[2] == "*")
		}
	}
	table := NSEScript[strings.Index(NSEScript, "local CP1252 = {"):]
	table = table[:strings.Index(table, "}")]
	codes := regexp.MustCompile(`0x([0-9A-F]{4})`).FindAllStringSubmatch(table, -1)
	if len(codes) != 32 {
		t.Fatalf("CP1252 has %d entries", len(codes))
	}
	for i, c := range codes {
		cp, _ := strconv.ParseInt(c[1], 16, 32)
		if got := html.UnescapeString("&#" + strconv.Itoa(0x80+i) + ";"); got != string(rune(cp)) {
			t.Errorf("&#%d; is %q in Go, U+%04X in athar.nse", 0x80+i, got, cp)
		}
	}
}

func TestLuaString(t *testing.T) {
	for in, want := range map[string]string{
		"plain":        `"plain"`,
		"自主":           `"自主"`,
		"a\"b\\c":      `"a\"b\\c"`,
		"\x00\x7f\r\n": `"\x00\x7f\r\n"`,
		"\xff\xfe":     `"\xff\xfe"`,
		"é\xff":        `"\xc3\xa9\xff"`,
	} {
		if got := luaString(in); got != want {
			t.Errorf("luaString(%q) = %s, want %s", in, got, want)
		}
	}
}
