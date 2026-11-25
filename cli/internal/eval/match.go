package eval

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"net/netip"
	"regexp"
	"strconv"
	"strings"
)

// Modifiers from spec section 6. Operators are mutually exclusive; flags combine
// with them.
var (
	operators = map[string]bool{
		"contains": true, "startswith": true, "endswith": true, "re": true,
		"exists": true, "gt": true, "gte": true, "lt": true, "lte": true, "cidr": true,
	}
	flags = map[string]bool{"all": true, "cased": true, "hex": true}
)

// fieldMatcher tests one field of a response, e.g. "http.title|contains: x".
type fieldMatcher struct {
	field  string
	all    bool           // every value must match (|all)
	exists *bool          // |exists: true/false, or a null value (exists: false)
	values []valueMatcher // OR, or AND with all
}

func (m *fieldMatcher) match(f Fields) bool {
	v, present := f[m.field]
	present = present && v != nil
	if m.exists != nil {
		return present == *m.exists
	}
	if !present {
		return false
	}
	for _, vm := range m.values {
		ok := anyElement(v, vm)
		if m.all && !ok {
			return false
		}
		if !m.all && ok {
			return true
		}
	}
	return m.all
}

// anyElement reports whether vm matches v, or any element of v if v is a list
// (e.g. tls.cert.san or a repeated header).
func anyElement(v any, vm valueMatcher) bool {
	if list, ok := v.([]any); ok {
		for _, e := range list {
			if e != nil && vm.match(e) {
				return true
			}
		}
		return false
	}
	return vm.match(v)
}

type valueMatcher interface{ match(v any) bool }

type regexMatcher struct{ re *regexp.Regexp }

func (m regexMatcher) match(v any) bool { return m.re.MatchString(toString(v)) }

type bytesMatcher struct {
	op  string
	val []byte
}

func (m bytesMatcher) match(v any) bool {
	b := []byte(toString(v))
	switch m.op {
	case "contains":
		return bytes.Contains(b, m.val)
	case "startswith":
		return bytes.HasPrefix(b, m.val)
	case "endswith":
		return bytes.HasSuffix(b, m.val)
	}
	return bytes.Equal(b, m.val)
}

type numberMatcher struct {
	op  string
	val float64
}

func (m numberMatcher) match(v any) bool {
	f, err := strconv.ParseFloat(toString(v), 64)
	if err != nil {
		return false
	}
	switch m.op {
	case "gt":
		return f > m.val
	case "gte":
		return f >= m.val
	case "lt":
		return f < m.val
	}
	return f <= m.val
}

type cidrMatcher struct{ prefix netip.Prefix }

func (m cidrMatcher) match(v any) bool {
	a, err := netip.ParseAddr(toString(v))
	return err == nil && m.prefix.Contains(a.Unmap())
}

// compileField builds the matcher for one "field|modifiers: value" entry.
func compileField(key string, value any) (*fieldMatcher, error) {
	parts := strings.Split(key, "|")
	m := &fieldMatcher{field: parts[0]}
	op := ""
	var cased, hexv bool
	for _, mod := range parts[1:] {
		switch {
		case operators[mod]:
			if op != "" {
				return nil, fmt.Errorf("%s: modifiers %q and %q can't be combined", key, op, mod)
			}
			op = mod
		case mod == "all":
			m.all = true
		case mod == "cased":
			cased = true
		case mod == "hex":
			hexv = true
		default:
			return nil, fmt.Errorf("%s: unknown modifier %q", key, mod)
		}
	}
	if hexv && op != "" && op != "contains" && op != "startswith" && op != "endswith" {
		return nil, fmt.Errorf("%s: hex only combines with contains, startswith or endswith", key)
	}

	if value == nil {
		if op != "" {
			return nil, fmt.Errorf("%s: null value can't take modifiers", key)
		}
		f := false
		m.exists = &f
		return m, nil
	}
	if op == "exists" {
		b, ok := value.(bool)
		if !ok {
			return nil, fmt.Errorf("%s: exists takes true or false", key)
		}
		m.exists = &b
		return m, nil
	}

	values, ok := value.([]any)
	if !ok {
		values = []any{value}
	}
	if len(values) == 0 {
		return nil, fmt.Errorf("%s: empty value list", key)
	}
	for _, v := range values {
		if v == nil {
			return nil, fmt.Errorf("%s: null inside a value list", key)
		}
		if _, isMap := v.(map[string]any); isMap {
			return nil, fmt.Errorf("%s: value must be a scalar or a list of scalars", key)
		}
		if _, isList := v.([]any); isList {
			return nil, fmt.Errorf("%s: value must be a scalar or a list of scalars", key)
		}
		vm, err := compileValue(op, toString(v), cased, hexv)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", key, err)
		}
		m.values = append(m.values, vm)
	}
	return m, nil
}

func compileValue(op, val string, cased, hexv bool) (valueMatcher, error) {
	switch op {
	case "gt", "gte", "lt", "lte":
		f, err := strconv.ParseFloat(val, 64)
		if err != nil {
			return nil, fmt.Errorf("%s needs a number, got %q", op, val)
		}
		return numberMatcher{op, f}, nil
	case "cidr":
		p, err := netip.ParsePrefix(val)
		if err != nil {
			return nil, err
		}
		return cidrMatcher{p.Masked()}, nil
	case "re":
		// As in Sigma, the expression is used as written: case-sensitive
		// unless it sets (?i) itself.
		re, err := regexp.Compile(val)
		if err != nil {
			return nil, err
		}
		return regexMatcher{re}, nil
	}

	if hexv {
		b, err := hex.DecodeString(strings.ReplaceAll(val, " ", ""))
		if err != nil {
			return nil, fmt.Errorf("invalid hex value %q", val)
		}
		return bytesMatcher{op, b}, nil
	}

	pat := wildcardToRegexp(val)
	switch op {
	case "contains":
	case "startswith":
		pat = "^" + pat
	case "endswith":
		pat = pat + "$"
	default:
		pat = "^" + pat + "$"
	}
	if cased {
		pat = "(?s)" + pat
	} else {
		pat = "(?is)" + pat
	}
	re, err := regexp.Compile(pat)
	if err != nil {
		return nil, err
	}
	return regexMatcher{re}, nil
}

// wildcardToRegexp converts a Sigma value to a regular expression: * matches
// any sequence, ? any single character, and \*, \? and \\ are literals. Any
// other backslash is a literal backslash.
func wildcardToRegexp(s string) string {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c == '\\' && i+1 < len(s) && (s[i+1] == '*' || s[i+1] == '?' || s[i+1] == '\\'):
			b.WriteString(regexp.QuoteMeta(s[i+1 : i+2]))
			i++
		case c == '*':
			b.WriteString(".*")
		case c == '?':
			b.WriteString(".")
		default:
			b.WriteString(regexp.QuoteMeta(s[i : i+1]))
		}
	}
	return b.String()
}

func toString(v any) string {
	switch x := v.(type) {
	case string:
		return x
	case []byte:
		return string(x)
	case int:
		return strconv.Itoa(x)
	case int64:
		return strconv.FormatInt(x, 10)
	case uint64:
		return strconv.FormatUint(x, 10)
	case float64:
		return strconv.FormatFloat(x, 'f', -1, 64)
	case bool:
		return strconv.FormatBool(x)
	}
	return fmt.Sprint(v)
}
