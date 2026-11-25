// Package probe turns targets and ports into service observations: it checks
// whether a port is open and collects the taxonomy fields of the baseline
// probe (banner, TLS, HTTP, favicon) and of opt-in custom probes.
package probe

import (
	"bufio"
	"fmt"
	"io"
	"math/bits"
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
// the loaded rules list under target.ports. It holds ports where the baseline
// probe (banner, TLS, HTTP) can see something; ports whose services answer
// none of these, such as SMB, are left out. athar scan -h prints the list.
var DefaultPorts = []int{
	// Common services: FTP, SSH, Telnet, mail, SOCKS, databases, remote desktop.
	21, 22, 23, 25, 110, 143, 465, 587, 993, 995, 1080, 1433, 1521, 2222, 3306,
	3389, 5432, 5900, 6379, 27017,
	// Web, alternative web ports and admin consoles (cPanel, GlassFish,
	// Kibana, WebLogic, Splunk, Nessus, RabbitMQ, Webmin and others).
	80, 81, 82, 88, 443, 591, 2082, 2083, 2086, 2087, 3000, 3001, 4443, 4848,
	5000, 5001, 5443, 5601, 7000, 7001, 7070, 7080, 7777, 8000, 8001, 8002,
	8008, 8010, 8080, 8081, 8082, 8083, 8085, 8088, 8089, 8090, 8091, 8180,
	8181, 8280, 8443, 8800, 8834, 8880, 8888, 8899, 9000, 9001, 9080, 9090,
	9091, 9093, 9200, 9443, 9999, 10000, 10443, 15672, 18080,
	// Containers and infrastructure APIs: Docker, etcd, WinRM, Kubernetes,
	// Proxmox, Consul, kubelet.
	2375, 2376, 2379, 5985, 5986, 6443, 8006, 8500, 10250,
	// AI and LLM tools: LibreChat, LiteLLM, Vite, n8n, TensorBoard, Gradio,
	// ComfyUI, Ray, Streamlit, agentic consoles on 8787, Ollama.
	3080, 4000, 5173, 5678, 6006, 7860, 8188, 8265, 8501, 8787, 11434,
	// C2 and offensive tools: Empire, Metasploit, Mythic, Sliver, Havoc,
	// Cobalt Strike, Metasploit RPC.
	1337, 4444, 7443, 31337, 40056, 50050, 55553,
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
			n := int(size(t))
			hosts += n
			checks += n * len(ports)
		default:
			hosts++
			checks += len(ports)
		}
	}
	return hosts, checks
}

// Each calls fn for every host and port. It walks port by port; within a
// port it visits the hosts of all targets in a spread order, so consecutive
// checks go to hosts far apart (different /24s of a /16, different targets of
// a list) instead of to neighbours. host:port targets come last, in order. It
// stops when fn returns false.
func Each(targets []Target, ports []int, fn func(host string, port int) bool) {
	// hosts holds the ranges and single hosts; ends[k] is the number of
	// addresses in hosts[:k+1].
	var hosts []Target
	var ends []uint64
	var n uint64
	for _, t := range targets {
		if t.Port != 0 {
			continue
		}
		n += size(t)
		hosts = append(hosts, t)
		ends = append(ends, n)
	}
	step := spreadStep(n)
	for _, port := range ports {
		for i := uint64(0); i < n; i++ {
			hi, lo := bits.Mul64(i, step)
			j := bits.Rem64(hi, lo, n)
			k := sort.Search(len(ends), func(k int) bool { return ends[k] > j })
			t, host := hosts[k], hosts[k].Host
			if t.Prefix.IsValid() {
				host = nthAddr(t.Prefix, j-(ends[k]-size(t))).String()
			}
			if !fn(host, port) {
				return
			}
		}
	}
	for _, t := range targets {
		if t.Port != 0 && !fn(t.Host, t.Port) {
			return
		}
	}
}

// size is the number of hosts a range or host target expands to.
func size(t Target) uint64 {
	if t.Prefix.IsValid() {
		return 1 << (t.Prefix.Addr().BitLen() - t.Prefix.Bits())
	}
	return 1
}

// spreadStep returns a step coprime to n close to n divided by the golden
// ratio. Then i*step mod n visits every index below n once, and consecutive
// indexes land far apart and evenly spread (Fibonacci hashing).
func spreadStep(n uint64) uint64 {
	if n < 3 {
		return 1
	}
	s := uint64(float64(n) * 0.6180339887498949)
	for gcd(s, n) != 1 {
		s++
	}
	return s
}

func gcd(a, b uint64) uint64 {
	for b != 0 {
		a, b = b, a%b
	}
	return a
}

// nthAddr returns the address at offset off in the range p.
func nthAddr(p netip.Prefix, off uint64) netip.Addr {
	b := p.Addr().AsSlice()
	for i := len(b) - 1; i >= 0 && off > 0; i-- {
		off += uint64(b[i])
		b[i] = byte(off)
		off >>= 8
	}
	a, _ := netip.AddrFromSlice(b)
	return a
}
