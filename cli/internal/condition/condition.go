// Package condition parses and evaluates Sigma detection conditions:
// named selections combined with and, or, not, parentheses,
// "1 of <pattern>", "all of <pattern>", "1 of them" and "all of them".
//
// Precedence, from strongest to weakest: "x of", not, and, or.
package condition

import (
	"fmt"
	"regexp"
	"sort"
	"strings"
)

// Node is a parsed condition. Patterns are already expanded into the
// selection names they match.
type Node interface {
	// Eval evaluates the condition given the truth value of each selection.
	Eval(truth map[string]bool) bool
	// Names appends the selection names the condition refers to.
	Names(dst []string) []string
}

type ident string
type not struct{ x Node }
type and []Node
type or []Node

func (n ident) Eval(t map[string]bool) bool { return t[string(n)] }
func (n not) Eval(t map[string]bool) bool   { return !n.x.Eval(t) }
func (n and) Eval(t map[string]bool) bool {
	for _, x := range n {
		if !x.Eval(t) {
			return false
		}
	}
	return true
}
func (n or) Eval(t map[string]bool) bool {
	for _, x := range n {
		if x.Eval(t) {
			return true
		}
	}
	return false
}

func (n ident) Names(dst []string) []string { return append(dst, string(n)) }
func (n not) Names(dst []string) []string   { return n.x.Names(dst) }
func (n and) Names(dst []string) []string {
	for _, x := range n {
		dst = x.Names(dst)
	}
	return dst
}
func (n or) Names(dst []string) []string {
	for _, x := range n {
		dst = x.Names(dst)
	}
	return dst
}

// Parse parses cond. names are the selection names defined in the rule; an
// identifier that is not among them is an error, and so is a pattern that
// matches none of them.
func Parse(cond string, names []string) (Node, error) {
	toks := tokenize(cond)
	if len(toks) == 0 {
		return nil, fmt.Errorf("empty condition")
	}
	sorted := append([]string(nil), names...)
	sort.Strings(sorted)
	p := &parser{toks: toks, names: sorted}
	n, err := p.or()
	if err != nil {
		return nil, err
	}
	if p.pos < len(p.toks) {
		return nil, fmt.Errorf("unexpected %q", p.toks[p.pos])
	}
	return n, nil
}

func tokenize(s string) []string {
	s = strings.NewReplacer("(", " ( ", ")", " ) ").Replace(s)
	return strings.Fields(s)
}

type parser struct {
	toks  []string
	pos   int
	names []string
}

func (p *parser) peek() string {
	if p.pos < len(p.toks) {
		return strings.ToLower(p.toks[p.pos])
	}
	return ""
}

func (p *parser) next() string {
	t := p.toks[p.pos]
	p.pos++
	return t
}

func (p *parser) or() (Node, error) {
	x, err := p.and()
	if err != nil {
		return nil, err
	}
	n := or{x}
	for p.peek() == "or" {
		p.next()
		y, err := p.and()
		if err != nil {
			return nil, err
		}
		n = append(n, y)
	}
	if len(n) == 1 {
		return n[0], nil
	}
	return n, nil
}

func (p *parser) and() (Node, error) {
	x, err := p.unary()
	if err != nil {
		return nil, err
	}
	n := and{x}
	for p.peek() == "and" {
		p.next()
		y, err := p.unary()
		if err != nil {
			return nil, err
		}
		n = append(n, y)
	}
	if len(n) == 1 {
		return n[0], nil
	}
	return n, nil
}

func (p *parser) unary() (Node, error) {
	if p.peek() == "not" {
		p.next()
		x, err := p.unary()
		if err != nil {
			return nil, err
		}
		return not{x}, nil
	}
	return p.primary()
}

func (p *parser) primary() (Node, error) {
	switch t := p.peek(); t {
	case "":
		return nil, fmt.Errorf("unexpected end of condition")
	case "(":
		p.next()
		x, err := p.or()
		if err != nil {
			return nil, err
		}
		if p.peek() != ")" {
			return nil, fmt.Errorf("missing closing parenthesis")
		}
		p.next()
		return x, nil
	case ")", "and", "or", "of", "them":
		return nil, fmt.Errorf("unexpected %q", p.toks[p.pos])
	case "1", "all":
		p.next()
		if p.peek() != "of" {
			return nil, fmt.Errorf("expected \"of\" after %q", t)
		}
		p.next()
		if p.peek() == "" {
			return nil, fmt.Errorf("expected a pattern or \"them\" after \"%s of\"", t)
		}
		matched, err := p.expand(p.next())
		if err != nil {
			return nil, err
		}
		nodes := make([]Node, len(matched))
		for i, m := range matched {
			nodes[i] = ident(m)
		}
		if len(nodes) == 1 {
			return nodes[0], nil
		}
		if t == "1" {
			return or(nodes), nil
		}
		return and(nodes), nil
	default:
		name := p.next()
		if !contains(p.names, name) {
			return nil, fmt.Errorf("unknown selection %q", name)
		}
		return ident(name), nil
	}
}

// expand resolves "them" or a pattern with * wildcards to selection names.
// As in Sigma, "them" skips selections whose name starts with an underscore.
func (p *parser) expand(pattern string) ([]string, error) {
	var out []string
	if strings.ToLower(pattern) == "them" {
		for _, n := range p.names {
			if !strings.HasPrefix(n, "_") {
				out = append(out, n)
			}
		}
	} else {
		re := regexp.MustCompile("^" + strings.ReplaceAll(regexp.QuoteMeta(pattern), `\*`, ".*") + "$")
		for _, n := range p.names {
			if re.MatchString(n) {
				out = append(out, n)
			}
		}
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("%q matches no selection", pattern)
	}
	return out, nil
}

func contains(list []string, s string) bool {
	i := sort.SearchStrings(list, s)
	return i < len(list) && list[i] == s
}
