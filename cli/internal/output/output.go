// Package output writes identity records (spec section 7), either as
// readable lines for people or as JSON lines for tools.
package output

import (
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"strings"
	"sync"

	"github.com/Athar-HQ/Athar/cli/internal/color"
)

// Record is one matched service.
type Record struct {
	Target     string            `json:"target"`       // host:port as scanned
	IP         string            `json:"ip,omitempty"` // set when the target is a hostname
	TLS        bool              `json:"tls"`
	Rule       string            `json:"rule"`
	Title      string            `json:"title"`
	Author     string            `json:"author,omitempty"` // the rule's author; DRL 1.1 asks match messages to keep it
	Product    string            `json:"product,omitempty"`
	Vendor     string            `json:"vendor,omitempty"`
	Family     string            `json:"family,omitempty"`
	Category   string            `json:"category,omitempty"`
	CPE        string            `json:"cpe,omitempty"`
	Extracted  map[string]string `json:"extracted,omitempty"`
	Confidence string            `json:"confidence"`
	Matched    []string          `json:"matched"`
	Probes     []string          `json:"probes"`
	Observed   string            `json:"observed"`
}

// Sink receives records. Implementations are safe for concurrent use.
type Sink interface {
	Write(Record) error
}

// JSON writes one JSON object per line.
type JSON struct {
	mu  sync.Mutex
	enc *json.Encoder
}

func NewJSON(w io.Writer) *JSON {
	enc := json.NewEncoder(w)
	enc.SetEscapeHTML(false)
	return &JSON{enc: enc}
}

func (j *JSON) Write(r Record) error {
	j.mu.Lock()
	defer j.mu.Unlock()
	return j.enc.Encode(r)
}

// Text writes one readable line per record:
//
//	144.202.110.94:443 (tls)  Agentic Offensive Framework - ARTEX family  [offensive-tool] [high]  brand=ARGOS  by Gameel Ali (@MalGamy12)
type Text struct {
	mu sync.Mutex
	w  io.Writer
	c  color.Palette
}

func NewText(w io.Writer, c color.Palette) *Text {
	return &Text{w: w, c: c}
}

func (t *Text) Write(r Record) error {
	c := t.c
	var b strings.Builder
	b.WriteString(c.Bold(c.Cyan(r.Target)))
	var notes []string
	if r.IP != "" {
		notes = append(notes, r.IP)
	}
	if r.TLS {
		notes = append(notes, "tls")
	}
	if len(notes) > 0 {
		b.WriteString(" " + c.Dim("("+strings.Join(notes, ", ")+")"))
	}
	b.WriteString("  " + c.Bold(r.Title))
	b.WriteString("  ")
	if r.Category != "" {
		b.WriteString(c.Magenta("["+r.Category+"]") + " ")
	}
	b.WriteString(confidence(c, r.Confidence))
	if len(r.Extracted) > 0 {
		keys := make([]string, 0, len(r.Extracted))
		for k := range r.Extracted {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		b.WriteString(" ")
		for _, k := range keys {
			b.WriteString(" " + c.Dim(k+"=") + c.Bold(c.Yellow(r.Extracted[k])))
		}
	}
	if r.Author != "" {
		b.WriteString("  " + c.Dim("by "+r.Author))
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	_, err := fmt.Fprintln(t.w, b.String())
	return err
}

func confidence(c color.Palette, v string) string {
	s := "[" + v + "]"
	switch v {
	case "certain", "high":
		return c.Green(s)
	case "medium":
		return c.Yellow(s)
	}
	return c.Dim(s)
}
