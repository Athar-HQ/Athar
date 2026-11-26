package convert

import (
	"net"
	"testing"
	"time"

	"github.com/Athar-HQ/Athar/cli/internal/rule"
)

// holdServer runs handle on every connection, for at most 20 seconds.
func holdServer(t *testing.T, handle func(net.Conn)) int {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				c.SetDeadline(time.Now().Add(20 * time.Second))
				handle(c)
			}()
		}
	}()
	return ln.Addr().(*net.TCPAddr).Port
}

// TestNSEBannerReadIsBounded: as in athar scan, a server that drips bytes
// can't hold a banner read past athar.timeout, and a rule's read.timeout_ms
// can't extend a TCP probe's read past it.
func TestNSEBannerReadIsBounded(t *testing.T) {
	bin := nmapBin(t)
	for _, tt := range []struct {
		name   string
		handle func(net.Conn)
		rule   string
		match  bool
	}{
		{"drip", func(c net.Conn) {
			for {
				if _, err := c.Write([]byte("x")); err != nil {
					return
				}
				time.Sleep(50 * time.Millisecond)
			}
		}, `
title: bounded drip
id: 10000000-0000-4000-8000-0000000000b1
target: {protocol: tcp}
detection:
  selection:
    service.banner|startswith: 'xx'
  condition: selection
`, true},
		{"rule timeout", func(c net.Conn) {
			c.Read(make([]byte, 1))
		}, `
title: bounded rule timeout
id: 10000000-0000-4000-8000-0000000000b2
target: {protocol: http}
probes:
  hello:
    protocol: tcp
    read: {timeout_ms: 15000}
detection:
  selection:
    probe: hello
    service.banner|exists: true
  condition: selection
`, false},
	} {
		t.Run(tt.name, func(t *testing.T) {
			port := holdServer(t, tt.handle)
			r := parse(t, "bounded.yml", tt.rule)
			start := time.Now()
			got := runNSE(t, bin, []*rule.Rule{r}, []int{port}, "athar.probes", "athar.timeout=1s")
			if took := time.Since(start); took > 8*time.Second {
				t.Errorf("nmap took %v, want a read of at most 1s", took.Round(time.Millisecond))
			}
			if _, ok := got[port][r.ID]; ok != tt.match {
				t.Errorf("matched=%v, want %v", ok, tt.match)
			}
		})
	}
}
