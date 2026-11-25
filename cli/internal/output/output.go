// Package output writes identity records (spec section 7) as JSON lines.
package output

import (
	"encoding/json"
	"io"
	"sync"
)

// Record is one matched service.
type Record struct {
	Target     string            `json:"target"`       // host:port as scanned
	IP         string            `json:"ip,omitempty"` // set when the target is a hostname
	TLS        bool              `json:"tls"`
	Rule       string            `json:"rule"`
	Title      string            `json:"title"`
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

// Writer writes records as JSON lines. It is safe for concurrent use.
type Writer struct {
	mu  sync.Mutex
	enc *json.Encoder
}

func NewWriter(w io.Writer) *Writer {
	enc := json.NewEncoder(w)
	enc.SetEscapeHTML(false)
	return &Writer{enc: enc}
}

func (w *Writer) Write(r Record) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.enc.Encode(r)
}
