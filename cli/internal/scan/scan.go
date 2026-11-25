// Package scan runs rules against live services: it walks hosts and ports,
// probes each open port once, and evaluates every rule on what it saw.
package scan

import (
	"context"
	"fmt"
	"io"
	"net"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/Athar-HQ/Athar/cli/internal/eval"
	"github.com/Athar-HQ/Athar/cli/internal/output"
	"github.com/Athar-HQ/Athar/cli/internal/probe"
)

// Options control a scan.
type Options struct {
	Ports       []int
	Concurrency int           // parallel checks
	PerHost     int           // parallel checks per host
	Rate        int           // new connections per second; 0 means no limit
	Timeout     time.Duration // connect, handshake and read timeout
	Probes      bool          // send the custom probes rules declare
	UserAgent   string
	Log         io.Writer // receives one line per open port; nil for none
}

// Stats summarise a scan.
type Stats struct {
	Hosts, Checks int
	Open, Matches int64
	Elapsed       time.Duration
	Interrupted   bool
}

// unsupported are taxonomy fields the scanner does not collect yet.
var unsupported = map[string]bool{
	"tls.jarm": true, "tls.ja3s": true, "tls.ja4s": true, "tls.cert.ja4x": true,
	"ssh.hostkey.sha256": true, "ssh.kex_algorithms": true,
}

// Scanner evaluates a fixed set of rules against services.
type Scanner struct {
	rules  []*eval.Compiled
	opts   Options
	prober *probe.Prober
	// custom maps each rule to its probe ids and their dedup keys.
	custom   map[*eval.Compiled]map[string]string
	warnings []string
}

// New prepares a scanner. It works out which parts of the baseline probe
// the rules need and which custom probes to send.
func New(rules []*eval.Compiled, opts Options) *Scanner {
	s := &Scanner{rules: rules, opts: opts, custom: map[*eval.Compiled]map[string]string{}}
	needs := probe.Needs{}
	var customProbes []probe.CustomProbe
	seenKey := map[string]bool{}
	withProbes := 0

	for _, c := range rules {
		r := c.Rule
		if r.Target.Transport == "udp" {
			s.warnings = append(s.warnings, fmt.Sprintf("%s: UDP is not supported yet; rule skipped", r.Path))
			continue
		}
		used := c.FieldsUsed()
		proto := strings.ToLower(r.Target.Protocol)
		if proto == "http" {
			needs.HTTP = true
		} else {
			needs.Banner = true
		}
		if r.Target.TLS != "none" {
			needs.TLS = true
		}
		var missing []string
		for _, fields := range used {
			for _, f := range fields {
				switch {
				case strings.HasPrefix(f, "http.favicon."):
					needs.HTTP, needs.Favicon = true, true
				case strings.HasPrefix(f, "http."):
					needs.HTTP = true
				case strings.HasPrefix(f, "tls."):
					needs.TLS = true
				case strings.HasPrefix(f, "ssh."):
					needs.Banner = true
				}
				if unsupported[f] || strings.HasPrefix(f, "x-") {
					missing = append(missing, f)
				}
			}
		}
		if len(missing) > 0 {
			sort.Strings(missing)
			s.warnings = append(s.warnings, fmt.Sprintf("%s: athar scan does not collect %s; selections on it never match", r.Path, strings.Join(dedup(missing), ", ")))
		}

		if len(r.Probes) == 0 {
			continue
		}
		withProbes++
		if !opts.Probes {
			continue
		}
		s.custom[c] = map[string]string{}
		for id, p := range r.Probes {
			key := probe.ProbeKey(p)
			s.custom[c][id] = key
			if !seenKey[key] {
				seenKey[key] = true
				customProbes = append(customProbes, probe.CustomProbe{Key: key, Probe: p})
			}
		}
	}
	if withProbes > 0 && !opts.Probes {
		s.warnings = append(s.warnings, fmt.Sprintf("%d rule(s) declare custom probes, which are only sent with -probes; selections on them never match", withProbes))
	}
	sort.Slice(customProbes, func(i, j int) bool { return customProbes[i].Key < customProbes[j].Key })

	s.prober = &probe.Prober{
		Timeout:    opts.Timeout,
		BannerWait: min(opts.Timeout, 2*time.Second),
		UserAgent:  opts.UserAgent,
		Needs:      needs,
		Custom:     customProbes,
	}
	return s
}

// Warnings lists rule parts the scan can't evaluate as written.
func (s *Scanner) Warnings() []string { return s.warnings }

// Needs reports which parts of the baseline probe will run.
func (s *Scanner) Needs() probe.Needs { return s.prober.Needs }

// Run scans every host and port of the targets and writes one record per
// matched service. It returns when all checks are done or ctx is cancelled.
func (s *Scanner) Run(ctx context.Context, targets []probe.Target, w *output.Writer) Stats {
	start := time.Now()
	var st Stats
	st.Hosts, st.Checks = probe.Count(targets, s.opts.Ports)

	if s.opts.Rate > 0 {
		ticker := time.NewTicker(time.Second / time.Duration(s.opts.Rate))
		defer ticker.Stop()
		s.prober.Limit = func(ctx context.Context) error {
			select {
			case <-ticker.C:
				return nil
			case <-ctx.Done():
				return ctx.Err()
			}
		}
	}
	hosts := newHostLimiter(max(1, s.opts.PerHost))

	type job struct {
		host string
		port int
	}
	jobs := make(chan job, max(1, s.opts.Concurrency))
	go func() {
		defer close(jobs)
		probe.Each(targets, s.opts.Ports, func(host string, port int) bool {
			select {
			case jobs <- job{host, port}:
				return true
			case <-ctx.Done():
				return false
			}
		})
	}()

	var open, matches atomic.Int64
	var wg sync.WaitGroup
	for range max(1, s.opts.Concurrency) {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := range jobs {
				if ctx.Err() != nil {
					continue
				}
				release := hosts.acquire(j.host)
				svc := s.prober.Probe(ctx, j.host, j.port)
				release()
				if svc == nil {
					continue
				}
				open.Add(1)
				s.logOpen(svc)
				for _, rec := range s.Evaluate(svc) {
					if err := w.Write(rec); err == nil {
						matches.Add(1)
					}
				}
			}
		}()
	}
	wg.Wait()

	st.Open, st.Matches = open.Load(), matches.Load()
	st.Elapsed = time.Since(start)
	st.Interrupted = ctx.Err() != nil
	return st
}

var confidenceRank = map[string]int{"certain": 4, "high": 3, "medium": 2, "low": 1}

// Evaluate runs every rule on one observed service and returns the records,
// most specific first. A family rule is dropped when one of its variants
// matched the same service (spec section 7).
func (s *Scanner) Evaluate(svc *probe.Service) []output.Record {
	type hit struct {
		c      *eval.Compiled
		res    eval.Result
		probes []string
	}
	var hits []hit
	for _, c := range s.rules {
		r := c.Rule
		if r.Target.Transport == "udp" {
			continue
		}
		if (r.Target.TLS == "required" && !svc.TLS) || (r.Target.TLS == "none" && svc.TLS) {
			continue
		}
		resp := eval.Responses{eval.DefaultProbe: svc.Fields}
		probes := []string{eval.DefaultProbe}
		for id, key := range s.custom[c] {
			if f, ok := svc.Custom[key]; ok {
				resp[id] = f
				probes = append(probes, id)
			}
		}
		if res := c.Eval(resp); res.Match {
			sort.Strings(probes[1:])
			hits = append(hits, hit{c, res, probes})
		}
	}

	matched := map[string]bool{}
	for _, h := range hits {
		matched[h.c.Rule.ID] = true
	}
	superseded := map[string]bool{}
	for _, h := range hits {
		for _, rel := range h.c.Rule.Related {
			if rel.Type == "variant-of" && matched[rel.ID] {
				superseded[rel.ID] = true
			}
		}
	}

	target := net.JoinHostPort(svc.Host, strconv.Itoa(svc.Port))
	ip := ""
	if svc.IP != svc.Host {
		ip = svc.IP
	}
	now := time.Now().UTC().Format(time.RFC3339)
	var out []output.Record
	for _, h := range hits {
		r := h.c.Rule
		if superseded[r.ID] {
			continue
		}
		out = append(out, output.Record{
			Target:     target,
			IP:         ip,
			TLS:        svc.TLS,
			Rule:       r.ID,
			Title:      r.Title,
			Product:    r.Identifies.Product,
			Vendor:     r.Identifies.Vendor,
			Family:     r.Identifies.Family,
			Category:   r.Identifies.Category,
			CPE:        r.Identifies.CPE,
			Extracted:  h.res.Extracted,
			Confidence: r.Confidence,
			Matched:    h.res.Matched,
			Probes:     h.probes,
			Observed:   now,
		})
	}
	sort.SliceStable(out, func(i, j int) bool {
		if a, b := confidenceRank[out[i].Confidence], confidenceRank[out[j].Confidence]; a != b {
			return a > b
		}
		return out[i].Title < out[j].Title
	})
	return out
}

func (s *Scanner) logOpen(svc *probe.Service) {
	if s.opts.Log == nil {
		return
	}
	parts := []string{"open", net.JoinHostPort(svc.Host, strconv.Itoa(svc.Port))}
	if svc.TLS {
		parts = append(parts, "tls")
	}
	if code, ok := svc.Fields["http.status_code"]; ok {
		parts = append(parts, fmt.Sprintf("http %v", code))
		if t, ok := svc.Fields["http.title"].(string); ok && t != "" {
			parts = append(parts, strconv.Quote(truncate(t, 60)))
		}
	} else if b, ok := svc.Fields["ssh.banner"].(string); ok {
		parts = append(parts, strconv.Quote(b))
	} else if b, ok := svc.Fields["service.banner"].(string); ok {
		parts = append(parts, "banner "+strconv.Quote(truncate(b, 60)))
	}
	if len(parts) == 2 {
		// The port accepted the connection but answered nothing the scanner
		// tried. Say so, rather than leaving the line looking incomplete.
		if tried := s.tried(); tried != "" {
			parts = append(parts, "no response (tried "+tried+")")
		}
	}
	fmt.Fprintln(s.opts.Log, strings.Join(parts, " "))
}

// tried lists the parts of the baseline probe the scanner sends, in order.
func (s *Scanner) tried() string {
	n := s.prober.Needs
	var t []string
	if n.Banner {
		t = append(t, "banner")
	}
	if n.TLS {
		t = append(t, "TLS")
	}
	if n.HTTP {
		t = append(t, "HTTP")
	}
	return strings.Join(t, ", ")
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}

func dedup(sorted []string) []string {
	var out []string
	for i, v := range sorted {
		if i == 0 || v != sorted[i-1] {
			out = append(out, v)
		}
	}
	return out
}

// hostLimiter caps parallel checks per host.
type hostLimiter struct {
	mu sync.Mutex
	n  int
	m  map[string]chan struct{}
}

func newHostLimiter(n int) *hostLimiter {
	return &hostLimiter{n: n, m: map[string]chan struct{}{}}
}

func (h *hostLimiter) acquire(host string) (release func()) {
	h.mu.Lock()
	ch := h.m[host]
	if ch == nil {
		ch = make(chan struct{}, h.n)
		h.m[host] = ch
	}
	h.mu.Unlock()
	ch <- struct{}{}
	return func() { <-ch }
}
