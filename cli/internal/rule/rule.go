// Package rule loads Athar rules from YAML and checks their metadata.
// Detection logic is checked when a rule is compiled by package eval.
package rule

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"go.yaml.in/yaml/v3"
)

// Rule is one Athar rule (spec section 2).
type Rule struct {
	Path string `yaml:"-"`

	Title          string             `yaml:"title"`
	ID             string             `yaml:"id"`
	Related        []Related          `yaml:"related"`
	Status         string             `yaml:"status"`
	Description    string             `yaml:"description"`
	References     []string           `yaml:"references"`
	Author         string             `yaml:"author"`
	Date           string             `yaml:"date"`
	Modified       string             `yaml:"modified"`
	Tags           []string           `yaml:"tags"`
	Target         Target             `yaml:"target"`
	Probes         map[string]Probe   `yaml:"probes"`
	Detection      map[string]any     `yaml:"detection"`
	Identifies     Identifies         `yaml:"identifies"`
	Extract        map[string]Extract `yaml:"extract"`
	Confidence     string             `yaml:"confidence"`
	FalsePositives []string           `yaml:"falsepositives"`
	Tests          []Test             `yaml:"tests"`
	Native         map[string]string  `yaml:"native"`

	// unknownKeys are top-level keys the spec does not define.
	unknownKeys []string
	// nested are the problems checkNested found below the top level.
	nested []Problem
}

type Related struct {
	ID   string `yaml:"id"`
	Type string `yaml:"type"`
}

type Target struct {
	Protocol  string `yaml:"protocol"`
	Transport string `yaml:"transport"`
	TLS       string `yaml:"tls"`
	Ports     []int  `yaml:"ports"`
}

type Probe struct {
	Protocol string       `yaml:"protocol"`
	Request  *HTTPRequest `yaml:"request"`
	Send     string       `yaml:"send"`
	Read     *ReadLimits  `yaml:"read"`
}

type HTTPRequest struct {
	Method  string            `yaml:"method"`
	Path    string            `yaml:"path"`
	Headers map[string]string `yaml:"headers"`
}

type ReadLimits struct {
	MaxBytes  int `yaml:"max_bytes"`
	TimeoutMs int `yaml:"timeout_ms"`
}

type Identifies struct {
	Product  string `yaml:"product"`
	Vendor   string `yaml:"vendor"`
	Family   string `yaml:"family"`
	Category string `yaml:"category"`
	CPE      string `yaml:"cpe"`
}

type Extract struct {
	Field    string `yaml:"field"`
	Regex    string `yaml:"regex"`
	JSONPath string `yaml:"jsonpath"`
}

type Test struct {
	Name      string                    `yaml:"name"`
	Expect    string                    `yaml:"expect"`
	Response  map[string]any            `yaml:"response"`
	Probes    map[string]map[string]any `yaml:"probes"` // custom probe responses, by probe id
	Extracted map[string]string         `yaml:"extracted"`
}

var knownKeys = map[string]bool{
	"title": true, "id": true, "related": true, "status": true, "description": true,
	"references": true, "author": true, "date": true, "modified": true, "tags": true,
	"target": true, "probes": true, "detection": true, "identifies": true, "extract": true,
	"confidence": true, "falsepositives": true, "tests": true, "native": true,
}

// Parse decodes one rule from YAML. path is only used in messages.
func Parse(data []byte, path string) (*Rule, error) {
	var top map[string]any
	dec := yaml.NewDecoder(bytes.NewReader(data))
	if err := dec.Decode(&top); err != nil {
		if errors.Is(err, io.EOF) {
			return nil, fmt.Errorf("%s: empty file", path)
		}
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	var extra any
	if err := dec.Decode(&extra); !errors.Is(err, io.EOF) {
		return nil, fmt.Errorf("%s: more than one YAML document; use one rule per file", path)
	}

	r := &Rule{Path: path}
	if err := yaml.Unmarshal(data, r); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	if err := r.valuesAsWritten(data); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	for k := range top {
		if !knownKeys[k] {
			r.unknownKeys = append(r.unknownKeys, k)
		}
	}
	sort.Strings(r.unknownKeys)
	var doc yaml.Node
	if err := yaml.Unmarshal(data, &doc); err == nil && len(doc.Content) == 1 {
		r.nested = checkNested(doc.Content[0])
	}
	return r, nil
}

// Load reads and parses one rule file.
func Load(path string) (*Rule, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return Parse(data, path)
}

// Files returns the rule files (.yml, .yaml) under the given files or
// directories, sorted. Hidden directories are skipped. A file reached more
// than once (named twice, in a listed folder, through a symlink) is returned
// once, under the first path that led to it.
func Files(paths []string) ([]string, error) {
	var out []string
	seen := map[string]bool{}
	add := func(path string) {
		key := path
		if abs, err := filepath.Abs(path); err == nil {
			key = abs
		}
		if resolved, err := filepath.EvalSymlinks(key); err == nil {
			key = resolved
		}
		if !seen[key] {
			seen[key] = true
			out = append(out, path)
		}
	}
	for _, p := range paths {
		info, err := os.Stat(p)
		if err != nil {
			return nil, err
		}
		if !info.IsDir() {
			add(p)
			continue
		}
		err = filepath.WalkDir(p, func(path string, d fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if d.IsDir() {
				if path != p && strings.HasPrefix(d.Name(), ".") {
					return filepath.SkipDir
				}
				return nil
			}
			if ext := filepath.Ext(path); ext == ".yml" || ext == ".yaml" {
				add(path)
			}
			return nil
		})
		if err != nil {
			return nil, err
		}
	}
	sort.Strings(out)
	return out, nil
}
