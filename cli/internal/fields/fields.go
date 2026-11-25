// Package fields holds the Athar field taxonomy (spec section 5).
package fields

import "strings"

// taxonomy lists every field a rule may use, as defined in spec section 5.
var taxonomy = map[string]bool{
	"service.port":         true,
	"service.transport":    true,
	"service.protocol":     true,
	"service.banner":       true,
	"http.status_code":     true,
	"http.title":           true,
	"http.body":            true,
	"http.body.mmh3":       true,
	"http.body.sha256":     true,
	"http.headers_raw":     true,
	"http.favicon.mmh3":    true,
	"http.favicon.md5":     true,
	"http.favicon.sha256":  true,
	"tls.version":          true,
	"tls.cipher":           true,
	"tls.alpn":             true,
	"tls.jarm":             true,
	"tls.ja3s":             true,
	"tls.ja4s":             true,
	"tls.cert.subject.cn":  true,
	"tls.cert.subject.o":   true,
	"tls.cert.subject.dn":  true,
	"tls.cert.issuer.cn":   true,
	"tls.cert.issuer.o":    true,
	"tls.cert.issuer.dn":   true,
	"tls.cert.serial":      true,
	"tls.cert.sha256":      true,
	"tls.cert.sha1":        true,
	"tls.cert.san":         true,
	"tls.cert.self_signed": true,
	"tls.cert.ja4x":        true,
	"ssh.banner":           true,
	"ssh.hostkey.sha256":   true,
	"ssh.kex_algorithms":   true,
}

// HeaderPrefix starts a single-header field such as http.headers.server.
const HeaderPrefix = "http.headers."

// Keyword fields are searched by Sigma keyword selections (spec section 6).
var Keyword = []string{"service.banner", "http.headers_raw", "http.body"}

// typed lists the fields of type int or bool. All other fields hold strings.
var typed = map[string]bool{
	"service.port":         true,
	"http.status_code":     true,
	"http.body.mmh3":       true,
	"http.favicon.mmh3":    true,
	"tls.cert.self_signed": true,
}

// Typed reports whether name is a field whose value is a number or a boolean.
func Typed(name string) bool { return typed[name] }

// Known reports whether name is a taxonomy field, a single-header field with a
// lowercase name, or an engine-specific x-<engine>. field.
func Known(name string) bool {
	if taxonomy[name] {
		return true
	}
	if h, ok := strings.CutPrefix(name, HeaderPrefix); ok {
		return h != "" && h == strings.ToLower(h)
	}
	if rest, ok := strings.CutPrefix(name, "x-"); ok {
		engine, field, found := strings.Cut(rest, ".")
		return found && engine != "" && field != ""
	}
	return false
}

// EngineSpecific reports whether name is in an x-<engine>. namespace, which the
// scanner ignores.
func EngineSpecific(name string) bool {
	return strings.HasPrefix(name, "x-")
}
