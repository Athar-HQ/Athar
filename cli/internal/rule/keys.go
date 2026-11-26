package rule

import (
	"fmt"
	"strings"

	"go.yaml.in/yaml/v3"
)

// Keys the spec defines below the top level (sections 2 to 4, 7 and 9).
var (
	targetKeys     = set("protocol", "transport", "tls", "ports")
	identifiesKeys = set("product", "vendor", "family", "category", "cpe")
	relatedKeys    = set("id", "type")
	probeKeys      = set("protocol", "request", "send", "read")
	requestKeys    = set("method", "path", "headers")
	extractKeys    = set("field", "regex", "jsonpath")
	testKeys       = set("name", "expect", "response", "probes", "extracted")

	// readLimits are the keys of a probe's read block with their upper
	// bounds (spec section 4): 1 MiB and 30 seconds.
	readLimits = map[string]int{"max_bytes": 1 << 20, "timeout_ms": 30000}
)

// checkNested reports unknown keys below the top level and read limits that
// are out of range. It works on the YAML nodes: the decoded Rule has dropped
// unknown keys and cannot tell a missing limit from a zero.
func checkNested(root *yaml.Node) []Problem {
	var p []Problem
	unknown := func(n *yaml.Node, where string, known map[string]bool) {
		for _, kv := range pairs(n) {
			if !known[kv[0].Value] {
				p = append(p, errorf("line %d: %s: unknown key %q; known keys: %s", kv[0].Line, where, kv[0].Value, keys(known)))
			}
		}
	}
	for _, top := range pairs(root) {
		switch top[0].Value {
		case "target":
			unknown(top[1], "target", targetKeys)
		case "identifies":
			unknown(top[1], "identifies", identifiesKeys)
		case "related":
			for i, e := range items(top[1]) {
				unknown(e, fmt.Sprintf("related entry %d", i+1), relatedKeys)
			}
		case "extract":
			for _, e := range pairs(top[1]) {
				unknown(e[1], "extract "+e[0].Value, extractKeys)
			}
		case "tests":
			for i, e := range items(top[1]) {
				name := fmt.Sprintf("#%d", i+1)
				for _, kv := range pairs(e) {
					if kv[0].Value == "name" && kv[1].Value != "" {
						name = kv[1].Value
					}
				}
				unknown(e, fmt.Sprintf("test %q", name), testKeys)
			}
		case "probes":
			for _, e := range pairs(top[1]) {
				where := fmt.Sprintf("probe %q", e[0].Value)
				unknown(e[1], where, probeKeys)
				for _, kv := range pairs(e[1]) {
					switch kv[0].Value {
					case "request":
						for _, q := range pairs(kv[1]) {
							switch {
							case requestKeys[q[0].Value]:
							case q[0].Value == "body":
								p = append(p, errorf("line %d: %s: request.body is not allowed: probes send no body", q[0].Line, where))
							default:
								p = append(p, errorf("line %d: %s: request: unknown key %q; known keys: %s", q[0].Line, where, q[0].Value, keys(requestKeys)))
							}
						}
					case "read":
						for _, q := range pairs(kv[1]) {
							limit, ok := readLimits[q[0].Value]
							if !ok {
								p = append(p, errorf("line %d: %s: read: unknown key %q; known keys: %s", q[0].Line, where, q[0].Value, strings.Join(sortedKeys(readLimits), ", ")))
								continue
							}
							var n int
							if q[1].Decode(&n) == nil && (n < 1 || n > limit) {
								p = append(p, errorf("line %d: %s: read.%s %d is not between 1 and %d", q[0].Line, where, q[0].Value, n, limit))
							}
						}
					}
				}
			}
		}
	}
	return p
}

// pairs returns the keys and values of a mapping node. Another kind of node
// has none. Merge keys (<<) are skipped.
func pairs(n *yaml.Node) [][2]*yaml.Node {
	if n.Kind == yaml.AliasNode {
		n = n.Alias
	}
	if n.Kind != yaml.MappingNode {
		return nil
	}
	var out [][2]*yaml.Node
	for i := 0; i+1 < len(n.Content); i += 2 {
		if n.Content[i].Tag == "!!merge" {
			continue
		}
		out = append(out, [2]*yaml.Node{n.Content[i], n.Content[i+1]})
	}
	return out
}

// items returns the entries of a sequence node.
func items(n *yaml.Node) []*yaml.Node {
	if n.Kind == yaml.AliasNode {
		n = n.Alias
	}
	if n.Kind != yaml.SequenceNode {
		return nil
	}
	return n.Content
}
