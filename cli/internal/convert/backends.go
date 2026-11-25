package convert

import (
	"fmt"
	"net/textproto"
	"regexp"
	"strings"
)

// backend translates single terms and knows an engine's boolean syntax.
type backend interface {
	// term renders one term. ok is false when the engine can't express
	// it; note then says why.
	term(t term) (s string, f Fidelity, note string, ok bool)
	andOp() string
	orOp() string
	canOr() bool
	wrap(q string) string
}

var backends = map[string]backend{
	"fofa":    fofa{},
	"shodan":  shodan{},
	"censys":  censys{},
	"zoomeye": zoomeye{},
	"modat":   modat{},
}

// kind says how an engine searches a field.
type kind int

const (
	substring  kind = iota // substring search: contains is exact
	words                  // tokenised or whole-word search: contains is approximate
	exactOnly              // hashes and numbers: equality only
	rawHeaders             // the value is searched anywhere in the raw header block
	oneHeader              // Modat: one header by name and value
	fullText               // Shodan: a quoted phrase in the full banner text
)

type fieldSpec struct {
	name       string
	kind       kind
	regex      bool   // the engine supports regex on this field
	unverified bool   // mapping marked † in spec Appendix A
	note       string // known limitation, shown with every query that uses the field
}

// Engines index only part of large bodies (spec section 10, body truncation).
const (
	shodanBodyNote = "shodan does not index all of a large body; a body condition can miss hosts the scanner finds"
	censysBodyNote = "censys searches only the first 6 KB of some bodies; a body condition can miss hosts the scanner finds"
)

var (
	fofaFields = map[string]fieldSpec{
		"http.title":          {name: "title"},
		"http.body":           {name: "body"},
		"http.headers_raw":    {name: "header", kind: rawHeaders},
		"http.headers.server": {name: "server"},
		"http.status_code":    {name: "status_code", kind: exactOnly},
		"http.favicon.mmh3":   {name: "icon_hash", kind: exactOnly},
		"tls.cert.subject.cn": {name: "cert.subject.cn"},
		"tls.cert.issuer.cn":  {name: "cert.issuer.cn"},
		"tls.jarm":            {name: "jarm", kind: exactOnly},
		"service.banner":      {name: "banner"},
		"service.port":        {name: "port", kind: exactOnly},
	}
	zoomeyeFields = map[string]fieldSpec{
		"http.title":          {name: "title"},
		"http.body":           {name: "http.body"},
		"http.headers_raw":    {name: "http.header", kind: rawHeaders},
		"http.headers.server": {name: "http.header.server"},
		"http.status_code":    {name: "http.header.status_code", kind: exactOnly},
		"http.favicon.mmh3":   {name: "iconhash", kind: exactOnly},
		"http.favicon.md5":    {name: "iconhash", kind: exactOnly},
		"tls.cert.subject.cn": {name: "ssl.cert.subject.cn"},
		"tls.cert.issuer.cn":  {name: "ssl.cert.issuer.cn"},
		"tls.jarm":            {name: "ssl.jarm", kind: exactOnly},
		"tls.ja3s":            {name: "ssl.ja3s", kind: exactOnly},
		"service.banner":      {name: "banner"},
		"service.port":        {name: "port", kind: exactOnly},
	}
	shodanFields = map[string]fieldSpec{
		"http.title":          {name: "http.title", kind: words},
		"http.body":           {name: "http.html", kind: words, note: shodanBodyNote},
		"http.headers_raw":    {kind: fullText},
		"http.status_code":    {name: "http.status", kind: exactOnly},
		"http.favicon.mmh3":   {name: "http.favicon.hash", kind: exactOnly},
		"http.body.mmh3":      {name: "http.html_hash", kind: exactOnly, unverified: true},
		"tls.cert.subject.cn": {name: "ssl.cert.subject.cn", kind: words},
		"tls.cert.issuer.cn":  {name: "ssl.cert.issuer.cn", kind: words},
		"tls.jarm":            {name: "ssl.jarm", kind: exactOnly},
		"tls.ja3s":            {name: "ssl.ja3s", kind: exactOnly},
		"service.banner":      {kind: fullText},
		"service.port":        {name: "port", kind: exactOnly},
	}
	// Censys field names are relative to host.services, because every query
	// is wrapped in host.services: ( … ) to stay on one service.
	censysFields = map[string]fieldSpec{
		"http.title":          {name: "endpoints.http.html_title", kind: words, regex: true},
		"http.body":           {name: "endpoints.http.body", kind: words, regex: true, note: censysBodyNote},
		"http.status_code":    {name: "endpoints.http.status_code", kind: exactOnly, unverified: true},
		"http.favicon.sha256": {name: "endpoints.http.favicons.hash_sha256", kind: exactOnly},
		"http.body.sha256":    {name: "endpoints.http.body_hash_sha256", kind: exactOnly},
		"tls.cert.subject.cn": {name: "cert.parsed.subject.common_name", kind: words, regex: true, unverified: true},
		"tls.cert.issuer.cn":  {name: "cert.parsed.issuer.common_name", kind: words, regex: true, unverified: true},
		"tls.cert.sha256":     {name: "cert.fingerprint_sha256", kind: exactOnly},
		"tls.jarm":            {name: "jarm.fingerprint", kind: exactOnly},
		"service.banner":      {name: "banner", kind: words, regex: true},
		"service.port":        {name: "port", kind: exactOnly},
	}
	modatFields = map[string]fieldSpec{
		"http.title":          {name: "http.title", regex: true},
		"http.body":           {name: "http.body", kind: words},
		"http.headers_raw":    {name: "http.headers", kind: words},
		"http.status_code":    {name: "http.status_code", kind: exactOnly},
		"http.favicon.mmh3":   {name: "http.files.mmh3", kind: exactOnly},
		"http.favicon.sha256": {name: "http.files.sha256", kind: exactOnly},
		"http.body.mmh3":      {name: "http.body_mmh3", kind: exactOnly},
		"http.body.sha256":    {name: "http.body_sha256", kind: exactOnly},
		"tls.cert.subject.cn": {name: "tls.subject.common_name", regex: true},
		"tls.cert.issuer.cn":  {name: "tls.issuer.common_name", regex: true},
		"tls.cert.sha256":     {name: "tls.fingerprint_sha256", kind: exactOnly},
		"tls.jarm":            {name: "tls.jarm", kind: exactOnly},
		"tls.ja3s":            {name: "tls.ja3s", kind: exactOnly},
		"service.banner":      {name: "banner", kind: words},
		"service.port":        {name: "port", kind: exactOnly},
	}
)

// lookup applies the checks every engine shares and finds the field.
// Single headers (http.headers.<name>) map to the engine's header search.
func lookup(engine string, fields map[string]fieldSpec, headerKind kind, t term) (fieldSpec, string, bool) {
	switch t.op {
	case "null", "exists", "gt", "gte", "lt", "lte", "cidr":
		return fieldSpec{}, fmt.Sprintf("%s: %s can't express |%s", describe(t), engine, t.op), false
	}
	if t.hex {
		return fieldSpec{}, fmt.Sprintf("%s: %s can't search hex values", describe(t), engine), false
	}
	if rest, ok := strings.CutPrefix(t.field, "x-"); ok {
		eng, name, _ := strings.Cut(rest, ".")
		if eng != engine {
			return fieldSpec{}, fmt.Sprintf("%s is specific to %s", t.field, eng), false
		}
		return fieldSpec{name: name}, "", true
	}
	if spec, ok := fields[t.field]; ok {
		note := spec.note
		if spec.unverified {
			note = joinNote(note, fmt.Sprintf("the mapping of %s to %s is not verified against the %s docs yet", t.field, spec.name, engine))
		}
		return spec, note, true
	}
	if name, ok := strings.CutPrefix(t.field, "http.headers."); ok && headerKind != substring {
		if headerKind == rawHeaders {
			// One header is searched as its value in the raw header block.
			return fields["http.headers_raw"], "", true
		}
		return fieldSpec{name: name, kind: headerKind}, "", true
	}
	return fieldSpec{}, fmt.Sprintf("%s has no field for %s", engine, t.field), false
}

func noWildcards(engine string, t term) (string, bool) {
	if t.wild {
		return fmt.Sprintf("%s: %s can't search Sigma wildcards", describe(t), engine), false
	}
	return "", true
}

func joinNote(a, b string) string {
	switch {
	case a == "":
		return b
	case b == "":
		return a
	}
	return a + "; " + b
}

// ---- FOFA ----

type fofa struct{}

func (fofa) andOp() string        { return " && " }
func (fofa) orOp() string         { return " || " }
func (fofa) canOr() bool          { return true }
func (fofa) wrap(q string) string { return q }

func (fofa) term(t term) (string, Fidelity, string, bool) {
	return fofaLike("fofa", fofaFields, t, "==")
}

// fofaLike handles FOFA and ZoomEye, which share =, ==, != and quoting.
func fofaLike(engine string, fields map[string]fieldSpec, t term, exactOp string) (string, Fidelity, string, bool) {
	if note, ok := noWildcards(engine, t); !ok {
		return "", 0, note, false
	}
	if t.field == "" {
		if t.negated {
			return "", 0, fmt.Sprintf("%s can't negate a keyword", engine), false
		}
		return quote(t.value), Approximate, "", true
	}
	spec, note, ok := lookup(engine, fields, rawHeaders, t)
	if !ok {
		return "", 0, note, false
	}
	not := ""
	if t.negated {
		not = "!"
	}
	switch spec.kind {
	case exactOnly:
		if t.op != "eq" {
			return "", 0, fmt.Sprintf("%s: %s only supports equality on %s", describe(t), engine, spec.name), false
		}
		op := "="
		if t.negated {
			op = "!="
		}
		return spec.name + op + quote(t.value), Exact, note, true
	case rawHeaders:
		if t.op == "re" {
			return "", 0, fmt.Sprintf("%s: %s has no regex", describe(t), engine), false
		}
		return spec.name + not + "=" + quote(t.value), Approximate,
			joinNote(note, fmt.Sprintf("%s searches the whole header block for %q, not one header", engine, t.value)), true
	}
	f := Exact
	op := "="
	switch t.op {
	case "contains":
	case "eq":
		if t.negated {
			op, f = "", Approximate // != excludes every value that contains it
		} else {
			op = exactOp
			if engine == "zoomeye" && !t.cased {
				f = Approximate // ZoomEye's == is case-sensitive
			}
		}
	case "startswith", "endswith":
		f = Approximate
	default:
		return "", 0, fmt.Sprintf("%s: %s has no regex", describe(t), engine), false
	}
	if t.negated {
		op = "!="
	}
	return spec.name + op + quote(t.value), f, note, true
}

// ---- ZoomEye ----

type zoomeye struct{}

func (zoomeye) andOp() string        { return " && " }
func (zoomeye) orOp() string         { return " || " }
func (zoomeye) canOr() bool          { return true }
func (zoomeye) wrap(q string) string { return q }

func (zoomeye) term(t term) (string, Fidelity, string, bool) {
	return fofaLike("zoomeye", zoomeyeFields, t, "==")
}

// ---- Shodan ----

type shodan struct{}

func (shodan) andOp() string        { return " " }
func (shodan) orOp() string         { return "" }
func (shodan) canOr() bool          { return false }
func (shodan) wrap(q string) string { return q }

var shodanBare = regexp.MustCompile(`^[A-Za-z0-9._:-]+$`)

func (shodan) term(t term) (string, Fidelity, string, bool) {
	if note, ok := noWildcards("shodan", t); !ok {
		return "", 0, note, false
	}
	if t.op == "re" {
		return "", 0, describe(t) + ": shodan has no regex", false
	}
	if t.field == "" {
		if t.negated {
			return "", 0, "shodan can't negate a keyword", false
		}
		return quote(t.value), Approximate, "", true
	}
	spec, note, ok := lookup("shodan", shodanFields, fullText, t)
	if !ok {
		return "", 0, note, false
	}
	neg := ""
	if t.negated {
		neg = "-"
	}
	switch spec.kind {
	case fullText:
		if t.negated {
			return "", 0, "shodan can't negate a full-text phrase", false
		}
		phrase := t.value
		if strings.HasPrefix(t.field, "http.headers.") {
			phrase = textproto.CanonicalMIMEHeaderKey(spec.name) + ": " + t.value
		}
		return quote(phrase), Approximate, joinNote(note, fmt.Sprintf("shodan searches %s as full text", t.field)), true
	case exactOnly:
		if t.op != "eq" {
			return "", 0, fmt.Sprintf("%s: shodan only supports equality on %s", describe(t), spec.name), false
		}
		v := t.value
		if !shodanBare.MatchString(v) {
			v = quote(v)
		}
		return neg + spec.name + ":" + v, Exact, note, true
	}
	// Text filters match tokens, so every text operator is approximate.
	return neg + spec.name + ":" + quote(t.value), Approximate, note, true
}

// key lets an OR of positive values of one filter become a comma list,
// http.title:"a","b", which Shodan reads as a or b.
func (shodan) key(t term) (string, string) {
	if t.negated || t.field == "" || t.op == "re" || t.wild || t.hex {
		return "", ""
	}
	spec, ok := shodanFields[t.field]
	if !ok {
		return "", ""
	}
	switch spec.kind {
	case words:
		return spec.name, quote(t.value)
	case exactOnly:
		if t.op != "eq" {
			return "", ""
		}
		if shodanBare.MatchString(t.value) {
			return spec.name, t.value
		}
		return spec.name, quote(t.value)
	}
	return "", ""
}

func (shodan) list(field string, values []string) string {
	return field + ":" + strings.Join(values, ",")
}

// ---- Censys Platform ----

type censys struct{}

func (censys) andOp() string        { return " and " }
func (censys) orOp() string         { return " or " }
func (censys) canOr() bool          { return true }
func (censys) wrap(q string) string { return "host.services: (" + q + ")" }

func (censys) term(t term) (string, Fidelity, string, bool) {
	if note, ok := noWildcards("censys", t); !ok {
		return "", 0, note, false
	}
	if t.field == "" {
		return "", 0, "censys keywords can't be combined with host.services", false
	}
	if strings.HasPrefix(t.field, "http.headers") {
		return "", 0, fmt.Sprintf("%s: header search on censys is not verified yet", describe(t)), false
	}
	spec, note, ok := lookup("censys", censysFields, substring, t)
	if !ok {
		return "", 0, note, false
	}
	not := ""
	if t.negated {
		not = "not "
	}
	if spec.kind == exactOnly {
		if t.op != "eq" {
			return "", 0, fmt.Sprintf("%s: censys only supports equality on %s", describe(t), spec.name), false
		}
		return not + spec.name + " = " + quote(t.value), Exact, note, true
	}
	switch t.op {
	case "contains":
		// ":" is case-insensitive but tokenised.
		return not + spec.name + ": " + quote(t.value), Approximate, note, true
	case "eq":
		// "=" is exact but case-sensitive.
		f := Approximate
		if t.cased {
			f = Exact
		}
		return not + spec.name + " = " + quote(t.value), f, note, true
	case "startswith", "endswith", "re":
		if !spec.regex {
			return "", 0, fmt.Sprintf("%s: no regex on %s", describe(t), spec.name), false
		}
		re := t.raw
		switch t.op {
		case "startswith":
			re = "^" + regexLiteral(t.value)
		case "endswith":
			re = regexLiteral(t.value) + "$"
		}
		return not + spec.name + " =~ " + quoteRegex(re), Approximate,
			joinNote(note, "case sensitivity of censys regex is not documented"), true
	}
	return "", 0, describe(t) + ": not supported on censys", false
}

// ---- Modat Magnify ----

type modat struct{}

func (modat) andOp() string        { return " and " }
func (modat) orOp() string         { return " or " }
func (modat) canOr() bool          { return true }
func (modat) wrap(q string) string { return q }

var modatBare = regexp.MustCompile(`^-?[0-9]+$`)

func (modat) term(t term) (string, Fidelity, string, bool) {
	not := ""
	if t.negated {
		not = "not "
	}
	if t.field == "" {
		if t.negated || t.wild {
			return "", 0, "modat can't negate or wildcard a keyword", false
		}
		return quote(t.value), Approximate, "modat searches a bare phrase in eleven fields, not only banner, headers and body", true
	}
	spec, note, ok := lookup("modat", modatFields, oneHeader, t)
	if !ok {
		return "", 0, note, false
	}

	switch spec.kind {
	case exactOnly:
		if t.op != "eq" || t.wild {
			return "", 0, fmt.Sprintf("%s: modat only supports equality on %s", describe(t), spec.name), false
		}
		v := t.value
		if !modatBare.MatchString(v) {
			v = quote(v)
		}
		return not + spec.name + "=" + v, Exact, note, true

	case oneHeader:
		if t.wild {
			return "", 0, describe(t) + ": modat can't search wildcards in a header", false
		}
		key := textproto.CanonicalMIMEHeaderKey(spec.name)
		var cond string
		f := Exact
		switch {
		case t.op == "re":
			cond, f = "value =~ "+quoteRegex(t.raw), Approximate
		case t.cased:
			// Header values have no case-sensitive = or ~; use ==~.
			cond = "value ==~ " + quoteRegex(anchor(t))
		case t.op == "contains":
			cond = "value ~ " + quote(t.value)
		case t.op == "eq":
			cond = "value = " + quote(t.value)
		default:
			cond = "value =~ " + quoteRegex(anchor(t))
		}
		return not + "http.headers: (key = " + quote(key) + " and " + cond + ")", f, note, true

	case words:
		// Whole-word fields: exact equality works, substring search does not.
		if t.wild || t.op == "re" {
			return "", 0, fmt.Sprintf("%s: modat has no regex or wildcards on %s", describe(t), spec.name), false
		}
		if t.op == "eq" {
			op := "="
			if t.cased {
				op = "=="
			}
			return not + spec.name + op + quote(t.value), Exact, note, true
		}
		op := "~"
		if t.cased {
			op = "~~"
		}
		return not + spec.name + op + quote(t.value), Approximate,
			joinNote(note, fmt.Sprintf("modat matches whole words on %s", spec.name)), true
	}

	// Substring fields such as http.title.
	if t.wild {
		pattern := t.raw
		switch t.op {
		case "contains":
			pattern = "*" + pattern + "*"
		case "startswith":
			pattern += "*"
		case "endswith":
			pattern = "*" + pattern
		case "re":
			return "", 0, describe(t) + ": wildcards and regex together", false
		}
		op := "="
		if t.cased {
			op = "=="
		}
		return not + spec.name + op + quoteRegex(pattern), Exact, note, true
	}
	switch t.op {
	case "contains":
		op := "~"
		if t.cased {
			op = "~~"
		}
		return not + spec.name + op + quote(t.value), Exact, note, true
	case "eq":
		op := "="
		if t.cased {
			op = "=="
		}
		return not + spec.name + op + quote(t.value), Exact, note, true
	case "startswith", "endswith", "re":
		if !spec.regex {
			return "", 0, fmt.Sprintf("%s: no regex on %s", describe(t), spec.name), false
		}
		op := "=~"
		if t.cased {
			op = "==~"
		}
		if t.op == "re" {
			return not + spec.name + op + quoteRegex(t.raw), Approximate,
				joinNote(note, "modat's regex dialect is smaller than RE2"), true
		}
		return not + spec.name + op + quoteRegex(anchor(t)), Exact, note, true
	}
	return "", 0, describe(t) + ": not supported on modat", false
}

// anchor turns a literal condition into an anchored regex.
func anchor(t term) string {
	lit := regexLiteral(t.value)
	switch t.op {
	case "eq":
		return "^" + lit + "$"
	case "startswith":
		return "^" + lit
	case "endswith":
		return lit + "$"
	}
	return lit
}
