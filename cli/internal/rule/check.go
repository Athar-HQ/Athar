package rule

import (
	"fmt"
	"regexp"
	"sort"
	"strings"
)

// Severity of a Problem.
type Severity int

const (
	Warning Severity = iota
	Error
)

func (s Severity) String() string {
	if s == Error {
		return "error"
	}
	return "warning"
}

// Problem is one finding about a rule.
type Problem struct {
	Severity Severity
	Msg      string
}

func errorf(format string, a ...any) Problem {
	return Problem{Error, fmt.Sprintf(format, a...)}
}

func warnf(format string, a ...any) Problem {
	return Problem{Warning, fmt.Sprintf(format, a...)}
}

// Controlled values from the spec.
var (
	statuses    = set("experimental", "test", "stable", "deprecated", "unsupported")
	confidences = set("low", "medium", "high", "certain")
	transports  = set("tcp", "udp")
	tlsModes    = set("auto", "required", "none")
	expects     = set("match", "no_match")
	categories  = set("c2", "offensive-tool", "phishing-kit", "malware-panel", "remote-access",
		"ai-infrastructure", "network-appliance", "ics", "iot", "cms", "web-server", "database")
	relatedTypes = set("derived", "obsolete", "merged", "renamed", "similar", "variant-of")
)

// probeProtocols are the probes a scanner can send (spec section 4).
var probeProtocols = set("http", "tcp")

var uuidV4 = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)

func set(values ...string) map[string]bool {
	m := make(map[string]bool, len(values))
	for _, v := range values {
		m[v] = true
	}
	return m
}

// Check validates a rule's metadata against the spec. Detection, extraction and
// tests are checked by eval.Compile and eval.RunTests.
func Check(r *Rule) []Problem {
	var p []Problem

	for _, k := range r.unknownKeys {
		p = append(p, warnf("unknown top-level key %q", k))
	}
	p = append(p, r.nested...)

	if r.Title == "" {
		p = append(p, errorf("missing title"))
	}
	switch {
	case r.ID == "":
		p = append(p, errorf("missing id"))
	case !uuidV4.MatchString(r.ID):
		p = append(p, errorf("id %q is not a lowercase UUIDv4", r.ID))
	}
	switch {
	case r.Status == "":
		p = append(p, errorf("missing status"))
	case !statuses[r.Status]:
		p = append(p, errorf("status %q is not one of %s", r.Status, keys(statuses)))
	}
	switch {
	case r.Confidence == "":
		p = append(p, errorf("missing confidence"))
	case !confidences[r.Confidence]:
		p = append(p, errorf("confidence %q is not one of %s", r.Confidence, keys(confidences)))
	}

	for _, rel := range r.Related {
		if !uuidV4.MatchString(rel.ID) {
			p = append(p, errorf("related id %q is not a lowercase UUIDv4", rel.ID))
		}
		if !relatedTypes[rel.Type] {
			p = append(p, errorf("related type %q is not one of %s", rel.Type, keys(relatedTypes)))
		}
	}

	if r.Target.Protocol == "" {
		p = append(p, errorf("missing target.protocol"))
	}
	if r.Target.Transport != "" && !transports[r.Target.Transport] {
		p = append(p, errorf("target.transport %q is not one of %s", r.Target.Transport, keys(transports)))
	}
	if r.Target.TLS != "" && !tlsModes[r.Target.TLS] {
		p = append(p, errorf("target.tls %q is not one of %s", r.Target.TLS, keys(tlsModes)))
	}
	for _, port := range r.Target.Ports {
		if port < 1 || port > 65535 {
			p = append(p, errorf("target.ports: %d is not a port (1-65535)", port))
		}
	}

	for id, pr := range r.Probes {
		if id == "default" {
			p = append(p, errorf("probe id %q is reserved for the baseline probe", id))
		}
		switch strings.ToLower(pr.Protocol) {
		case "":
			p = append(p, errorf("probe %q: missing protocol", id))
		case "http":
		case "tcp":
			if _, err := Unescape(pr.Send); err != nil {
				p = append(p, errorf("probe %q: send: %v", id, err))
			}
		default:
			p = append(p, errorf("probe %q: protocol %q is not one of %s", id, pr.Protocol, keys(probeProtocols)))
		}
		for _, why := range pr.Unsafe() {
			p = append(p, errorf("probe %q: %s", id, why))
		}
	}

	if len(r.Detection) == 0 {
		p = append(p, errorf("missing detection"))
	}

	id := r.Identifies
	if id.Product == "" && id.Family == "" {
		p = append(p, errorf("identifies needs at least a product or a family"))
	}
	switch {
	case id.Category == "":
		p = append(p, errorf("missing identifies.category"))
	case !categories[id.Category]:
		p = append(p, errorf("identifies.category %q is not one of %s", id.Category, keys(categories)))
	}
	if id.Category != "" {
		var tagged bool
		for _, tag := range r.Tags {
			if c, ok := strings.CutPrefix(tag, "category."); ok {
				tagged = true
				if c != id.Category {
					p = append(p, errorf("tag %q does not repeat identifies.category %q", tag, id.Category))
				}
			}
		}
		if !tagged {
			p = append(p, warnf("no category.* tag; add category.%s", id.Category))
		}
	}

	var positive, negative bool
	for i, t := range r.Tests {
		name := t.Name
		if name == "" {
			name = fmt.Sprintf("#%d", i+1)
			p = append(p, errorf("test %s: missing name", name))
		}
		if !expects[t.Expect] {
			p = append(p, errorf("test %q: expect must be match or no_match", name))
		}
		if t.Expect == "match" {
			positive = true
		}
		if t.Expect == "no_match" {
			negative = true
		}
		if len(t.Response) == 0 && len(t.Probes) == 0 {
			p = append(p, errorf("test %q: missing response", name))
		}
		for _, id := range sortedKeys(t.Probes) {
			if _, ok := r.Probes[id]; !ok {
				p = append(p, errorf("test %q: probe %q is not declared under probes", name, id))
			}
		}
	}
	if !positive {
		p = append(p, warnf("no test with expect: match"))
	}
	if !negative {
		p = append(p, warnf("no test with expect: no_match"))
	}

	return p
}

// CheckSet runs checks that need the whole rule set: duplicate ids and
// variant-of links. It returns problems keyed by rule path. known are further
// rules that variant-of links may point to; they are not checked themselves.
func CheckSet(rules []*Rule, known ...*Rule) map[string][]Problem {
	out := map[string][]Problem{}
	byID := map[string]*Rule{}
	for _, r := range rules {
		if r.ID == "" {
			continue
		}
		if prev, ok := byID[r.ID]; ok {
			out[r.Path] = append(out[r.Path], errorf("id %s is already used by %s", r.ID, prev.Path))
			continue
		}
		byID[r.ID] = r
	}
	for _, r := range known {
		if r.ID != "" && byID[r.ID] == nil {
			byID[r.ID] = r
		}
	}
	for _, r := range rules {
		for _, rel := range r.Related {
			if rel.Type != "variant-of" {
				continue
			}
			family := byID[rel.ID]
			switch {
			case rel.ID == r.ID:
				family = r
			case family == nil:
				out[r.Path] = append(out[r.Path], warnf("variant-of %s: family rule not found in this rule set", rel.ID))
				continue
			case variantOf(byID, family, r.ID, map[*Rule]bool{}):
				out[r.Path] = append(out[r.Path], errorf("variant-of %s: cycle: that rule is in turn a variant of this one", rel.ID))
				continue
			}
			out[r.Path] = append(out[r.Path], checkVariant(r, family)...)
		}
	}
	return out
}

func keys(m map[string]bool) string {
	k := make([]string, 0, len(m))
	for v := range m {
		k = append(k, v)
	}
	sort.Strings(k)
	return strings.Join(k, ", ")
}

func sortedKeys[V any](m map[string]V) []string {
	k := make([]string, 0, len(m))
	for v := range m {
		k = append(k, v)
	}
	sort.Strings(k)
	return k
}
