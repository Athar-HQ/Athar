package rule

import (
	"strings"

	"go.yaml.in/yaml/v3"

	"github.com/Athar-HQ/Athar/cli/internal/fields"
)

// node keeps the YAML node of a value. The decoder resolves aliases and merge
// keys before it calls UnmarshalYAML, and leaves n nil for a null value.
type node struct{ n *yaml.Node }

func (v *node) UnmarshalYAML(n *yaml.Node) error {
	v.n = n
	return nil
}

// valuesAsWritten gives the values of string fields in detection and in test
// responses the text the author wrote. YAML reads an unquoted 0100, 2.0, 1_000,
// 0x1F, true or 2026-11-26 as a number, a boolean or a date, and turning that
// back into a string loses the original: 0100 would become "64". Numeric and
// boolean fields and the values of exists, gt, gte, lt and lte keep what YAML
// decoded.
func (r *Rule) valuesAsWritten(data []byte) error {
	var raw struct {
		Detection map[string]node `yaml:"detection"`
		Tests     []struct {
			Response map[string]node            `yaml:"response"`
			Probes   map[string]map[string]node `yaml:"probes"`
		} `yaml:"tests"`
	}
	if err := yaml.Unmarshal(data, &raw); err != nil {
		return err
	}
	for name, v := range raw.Detection {
		if name != "condition" {
			r.Detection[name] = selectionValue(v.n)
		}
	}
	for i, t := range raw.Tests {
		if i >= len(r.Tests) {
			break
		}
		for k, v := range t.Response {
			r.Tests[i].Response[k] = fieldValue(k, v.n)
		}
		for id, resp := range t.Probes {
			for k, v := range resp {
				r.Tests[i].Probes[id][k] = fieldValue(k, v.n)
			}
		}
	}
	return nil
}

// selectionValue rebuilds one selection: a map of fields, a list of such maps
// or a list of keywords.
func selectionValue(n *yaml.Node) any {
	switch {
	case n == nil:
		return nil
	case n.Kind == yaml.MappingNode:
		return fieldMap(n)
	case n.Kind == yaml.SequenceNode:
		out := make([]any, len(n.Content))
		for i, e := range elements(n) {
			if e.Kind == yaml.MappingNode {
				out[i] = fieldMap(e)
			} else {
				out[i] = written(e)
			}
		}
		return out
	}
	return decoded(n)
}

func fieldMap(n *yaml.Node) map[string]any {
	var m map[string]node
	_ = n.Decode(&m)
	out := make(map[string]any, len(m))
	for k, v := range m {
		out[k] = fieldValue(k, v.n)
	}
	return out
}

// fieldValue returns the value of one "field|modifiers" key of a selection
// or of one field of a test response.
func fieldValue(key string, n *yaml.Node) any {
	if n == nil {
		return nil
	}
	if key == "probe" || typedKey(key) {
		return decoded(n)
	}
	if n.Kind == yaml.SequenceNode {
		out := make([]any, len(n.Content))
		for i, e := range elements(n) {
			out[i] = written(e)
		}
		return out
	}
	return written(n)
}

// typedKey reports whether the value of a "field|modifiers" key is a number
// or a boolean, not a string.
func typedKey(key string) bool {
	parts := strings.Split(key, "|")
	typed := fields.Typed(parts[0])
	for _, mod := range parts[1:] {
		switch mod {
		case "hex":
			return false
		case "exists", "gt", "gte", "lt", "lte":
			typed = true
		}
	}
	return typed
}

// written returns the source text of a scalar that YAML does not read as a
// string, and the decoded value of anything else.
func written(n *yaml.Node) any {
	v := decoded(n)
	if _, isString := v.(string); v != nil && !isString && n.Kind == yaml.ScalarNode {
		return n.Value
	}
	return v
}

// elements returns the entries of a sequence, with aliases resolved.
func elements(n *yaml.Node) []*yaml.Node {
	out := make([]*yaml.Node, len(n.Content))
	for i, e := range n.Content {
		for e.Kind == yaml.AliasNode {
			e = e.Alias
		}
		out[i] = e
	}
	return out
}

func decoded(n *yaml.Node) any {
	if n == nil {
		return nil
	}
	var v any
	_ = n.Decode(&v)
	return v
}
