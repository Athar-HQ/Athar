// Package probe turns targets and ports into service observations: it checks
// whether a port is open and collects the taxonomy fields of the baseline
// probe (banner, TLS, HTTP, favicon) and of opt-in custom probes.
package probe

import (
	"bufio"
	"fmt"
	"io"
	"net"
	"net/netip"
	"sort"
	"strconv"
	"strings"
)

// MaxPrefixHosts limits a single CIDR target, so a typo like /8 does not
// start a scan of 16 million addresses.
const MaxPrefixHosts = 1 << 16

// DefaultPorts is checked when no port list is given, together with the ports
// the loaded rules list under target.ports.
var DefaultPorts = []int{
	21, 22, 23, 25, 80, 81, 110, 143, 443, 465, 587, 993, 995, 1080, 1433, 1521,
	2375, 2376, 3000, 3306, 3389, 5000, 5432, 5601, 5900, 6379, 6443, 7001, 7443,
	8000, 8008, 8080, 8081, 8088, 8443, 8888, 9000, 9090, 9200, 9443, 10000,
	27017, 50050,
}

// Target is one scan target: a host (IP or name), a CIDR range, or a host with
// a fixed port.
type Target struct {
	Host   string       // IP address or hostname; empty for a range
	Prefix netip.Prefix // valid for a CIDR range
	Port   int          // non-zero for host:port targets
}

// ParseTarget parses an IP address, hostname, CIDR range or host:port.
// IPv6 addresses with a port need brackets: [2001:db8::1]:443.
func ParseTarget(s string) (Target, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return Target{}, fmt.Errorf("empty target")
	}
	if strings.Contains(s, "://") {
		return Target{}, fmt.Errorf("target %q: give a host, range or host:port, not a URL", s)
	}
	if strings.Contains(s, "/") {
		p, err := netip.ParsePrefix(s)
		if err != nil {
			return Target{}, fmt.Errorf("target %q: invalid CIDR range", s)
		}
		p = p.Masked()
		if bits := p.Addr().BitLen() - p.Bits(); bits > 16 {
			return Target{}, fmt.Errorf("target %q: range has more than %d addresses; split it into /16 or smaller", s, MaxPrefixHosts)
		}
		return Target{Prefix: p}, nil
	}
	if a, err := netip.ParseAddr(s); err == nil {
		return Target{Host: a.String()}, nil
	}
	if host, port, err := net.SplitHostPort(s); err == nil {
		n, err := strconv.Atoi(port)
		if err != nil || n < 1 || n > 65535 {
			return Target{}, fmt.Errorf("target %q: invalid port", s)
		}
		if host == "" || strings.ContainsAny(host, " \t") {
			return Target{}, fmt.Errorf("target %q: invalid host", s)
		}
		if a, err := netip.ParseAddr(host); err == nil {
			host = a.String()
		}
		return Target{Host: host, Port: n}, nil
	}
	if strings.ContainsAny(s, " \t:[]") {
		return Target{}, fmt.Errorf("target %q: not an IP address, hostname, range or host:port", s)
	}
	return Target{Host: strings.TrimSuffix(s, ".")}, nil
}

// ReadTargets parses one target per line. Empty lines and lines starting with
// # are skipped.
func ReadTargets(r io.Reader) ([]Target, error) {
	var out []Target
	sc := bufio.NewScanner(r)
	for n := 1; sc.Scan(); n++ {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		t, err := ParseTarget(line)
		if err != nil {
			return nil, fmt.Errorf("line %d: %w", n, err)
		}
		out = append(out, t)
	}
	return out, sc.Err()
}

// ParsePorts parses a port list such as "22,80,443,8000-8100". Duplicates are
// removed; the order of first appearance is kept.
func ParsePorts(s string) ([]int, error) {
	var out []int
	seen := map[int]bool{}
	add := func(p int) {
		if !seen[p] {
			seen[p] = true
			out = append(out, p)
		}
	}
	for _, part := range strings.Split(s, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		lo, hi, isRange := strings.Cut(part, "-")
		a, err := parsePort(lo)
		if err != nil {
			return nil, err
		}
		b := a
		if isRange {
			if b, err = parsePort(hi); err != nil {
				return nil, err
			}
			if b < a {
				return nil, fmt.Errorf("port range %q: end is below start", part)
			}
		}
		for p := a; p <= b; p++ {
			add(p)
		}
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("empty port list")
	}
	return out, nil
}

func parsePort(s string) (int, error) {
	n, err := strconv.Atoi(strings.TrimSpace(s))
	if err != nil || n < 1 || n > 65535 {
		return 0, fmt.Errorf("invalid port %q", s)
	}
	return n, nil
}

// MergePorts returns the union of the given port lists, sorted.
func MergePorts(lists ...[]int) []int {
	seen := map[int]bool{}
	var out []int
	for _, l := range lists {
		for _, p := range l {
			if p >= 1 && p <= 65535 && !seen[p] {
				seen[p] = true
				out = append(out, p)
			}
		}
	}
	sort.Ints(out)
	return out
}

// Count returns the number of hosts and host/port checks the targets expand
// to with the given ports.
func Count(targets []Target, ports []int) (hosts, checks int) {
	for _, t := range targets {
		switch {
		case t.Port != 0:
			hosts++
			checks++
		case t.Prefix.IsValid():
			n := 1 << (t.Prefix.Addr().BitLen() - t.Prefix.Bits())
			hosts += n
			checks += n * len(ports)
		default:
			hosts++
			checks += len(ports)
		}
	}
	return hosts, checks
}

// Each calls fn for every host and port. It walks port by port, so
// consecutive checks go to different hosts. It stops when fn returns false.
func Each(targets []Target, ports []int, fn func(host string, port int) bool) {
	for _, port := range ports {
		for _, t := range targets {
			switch {
			case t.Port != 0:
				continue
			case t.Prefix.IsValid():
				for a := t.Prefix.Addr(); t.Prefix.Contains(a); a = a.Next() {
					if !fn(a.String(), port) {
						return
					}
				}
			default:
				if !fn(t.Host, port) {
					return
				}
			}
		}
	}
	for _, t := range targets {
		if t.Port != 0 && !fn(t.Host, t.Port) {
			return
		}
	}
}
