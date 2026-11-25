package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"time"

	"github.com/Athar-HQ/Athar/cli/internal/color"
	"github.com/Athar-HQ/Athar/cli/internal/eval"
	"github.com/Athar-HQ/Athar/cli/internal/output"
	"github.com/Athar-HQ/Athar/cli/internal/probe"
	"github.com/Athar-HQ/Athar/cli/internal/rule"
	"github.com/Athar-HQ/Athar/cli/internal/scan"
)

// lookupHost resolves the hostnames among the targets; tests replace it.
var lookupHost = net.DefaultResolver.LookupHost

type listFlag []string

func (l *listFlag) String() string     { return strings.Join(*l, ",") }
func (l *listFlag) Set(v string) error { *l = append(*l, v); return nil }

func cmdScan(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("scan", flag.ContinueOnError)
	fs.SetOutput(stderr)
	var rulePaths listFlag
	fs.Var(&rulePaths, "r", "rule file or folder (repeatable)")
	ports := fs.String("p", "", "ports to check, e.g. 22,80,443,8000-8100 (default: built-in list plus the rules' target.ports)")
	inputList := fs.String("iL", "", "read targets from a file, one per line (\"-\" for stdin)")
	outFile := fs.String("o", "", "write matches to this file instead of stdout")
	concurrency := fs.Int("c", 500, "parallel checks")
	perHost := fs.Int("per-host", 8, "parallel checks per host")
	rate := fs.Int("rate", 200, "new connections per second (0: no limit)")
	connectTimeout := fs.Duration("connect-timeout", 1500*time.Millisecond, "TCP connect timeout (at most -timeout)")
	timeout := fs.Duration("timeout", 3*time.Second, "handshake and read timeout")
	probes := fs.Bool("probes", false, "also send the custom probes rules declare")
	verbose := fs.Bool("v", false, "print every open port to stderr")
	jsonOut := fs.Bool("json", false, "print matches as JSON lines instead of readable lines")
	noColor := fs.Bool("no-color", false, "no colors (also set by the NO_COLOR environment variable)")
	fs.Usage = func() {
		fmt.Fprintln(stderr, "Usage: athar scan -r <rules> [flags] <target>...")
		fmt.Fprintln(stderr, "\nChecks every host and port, fingerprints open ports and prints the services")
		fmt.Fprintln(stderr, "that match a rule, one line each (JSON with -json). Targets are IP addresses,")
		fmt.Fprintln(stderr, "hostnames, CIDR ranges (up to /16) or host:port.")
		fmt.Fprintln(stderr, "\nExample: athar scan -r rules/ -p 80,443,8000-8100 10.0.0.0/24")
		fmt.Fprintln(stderr)
		fs.PrintDefaults()
		fmt.Fprintf(stderr, "\nBuilt-in ports:\n%s\n", wrapList(probe.MergePorts(probe.DefaultPorts), 78))
	}
	positional, err := parseFlags(fs, args)
	if err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return exitOK
		}
		return exitUsage
	}
	fail := func(format string, a ...any) int {
		fmt.Fprintf(stderr, "athar scan: "+format+"\n", a...)
		return exitUsage
	}

	switch {
	case len(rulePaths) == 0:
		return fail("no rules; use -r <rule file or folder>")
	case *concurrency < 1 || *perHost < 1:
		return fail("-c and -per-host must be at least 1")
	case *rate < 0 || *rate > 100000:
		return fail("-rate must be between 0 and 100000")
	case *timeout <= 0 || *connectTimeout <= 0:
		return fail("-timeout and -connect-timeout must be positive")
	}

	// Rules: refuse to scan with invalid rules.
	compiled, err := loadRules(rulePaths)
	if err != nil {
		return fail("%v", err)
	}

	// Targets.
	var targets []probe.Target
	for _, a := range positional {
		t, err := probe.ParseTarget(a)
		if err != nil {
			return fail("%v", err)
		}
		targets = append(targets, t)
	}
	if *inputList != "" {
		var r io.Reader = os.Stdin
		if *inputList != "-" {
			f, err := os.Open(*inputList)
			if err != nil {
				return fail("%v", err)
			}
			defer f.Close()
			r = f
		}
		more, err := probe.ReadTargets(r)
		if err != nil {
			return fail("%s: %v", *inputList, err)
		}
		targets = append(targets, more...)
	}
	if len(targets) == 0 {
		return fail("no targets; give hosts, ranges or host:port, or use -iL")
	}

	// Ports.
	var portList []int
	if *ports != "" {
		if portList, err = probe.ParsePorts(*ports); err != nil {
			return fail("-p: %v", err)
		}
	} else {
		lists := [][]int{probe.DefaultPorts}
		for _, c := range compiled {
			lists = append(lists, c.Rule.Target.Ports)
		}
		portList = probe.MergePorts(lists...)
	}

	// Output.
	var out io.Writer = stdout
	if *outFile != "" {
		f, err := os.Create(*outFile)
		if err != nil {
			return fail("%v", err)
		}
		defer f.Close()
		out = f
	}

	opts := scan.Options{
		Ports:       portList,
		Concurrency: *concurrency,
		PerHost:     *perHost,
		Rate:        *rate,
		Connect:     min(*connectTimeout, *timeout),
		Timeout:     *timeout,
		Probes:      *probes,
		UserAgent:   "Mozilla/5.0 (compatible; athar/" + versionString() + "; +https://github.com/Athar-HQ/Athar)",
		Lookup:      lookupHost,
	}
	ce := color.For(stderr, *noColor)
	if *verbose {
		opts.Log = stderr
		opts.LogColor = ce
	}
	s := scan.New(compiled, opts)
	for _, w := range s.Warnings() {
		fmt.Fprintln(stderr, ce.Yellow("warning:"), w)
	}

	var sink output.Sink = output.NewText(out, color.For(out, *noColor))
	if *jsonOut {
		sink = output.NewJSON(out)
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	targets, unresolved := s.Resolve(ctx, targets)
	for _, w := range unresolved {
		fmt.Fprintln(stderr, ce.Yellow("warning:"), w)
	}
	if len(targets) == 0 {
		return fail("no target resolves; nothing scanned")
	}
	st := s.Run(ctx, targets, sink)

	status := ""
	if st.Interrupted {
		status = ce.Yellow(" (interrupted)")
	}
	found := fmt.Sprintf("%d matches", st.Matches)
	if st.Matches == 1 {
		found = "1 match"
	}
	if st.Matches > 0 {
		found = ce.Bold(ce.Green(found))
	}
	fmt.Fprintf(stderr, "%s %s, %s, %d open, %s in %s%s\n",
		ce.Bold("athar scan:"), plural(st.Hosts, "host"), plural(st.Checks, "check"), st.Open, found,
		st.Elapsed.Round(100*time.Millisecond), status)
	if st.Interrupted {
		return exitUsage
	}
	return exitOK
}

// loadRules loads and compiles every rule and fails on the first rule with
// errors; athar verify gives the full report.
func loadRules(paths []string) ([]*eval.Compiled, error) {
	files, err := rule.Files(paths)
	if err != nil {
		return nil, err
	}
	if len(files) == 0 {
		return nil, fmt.Errorf("no .yml or .yaml files in %s", strings.Join(paths, ", "))
	}
	var rules []*rule.Rule
	var compiled []*eval.Compiled
	for _, f := range files {
		r, err := rule.Load(f)
		if err != nil {
			return nil, fmt.Errorf("%v (run athar verify for details)", err)
		}
		for _, p := range rule.Check(r) {
			if p.Severity == rule.Error {
				return nil, fmt.Errorf("%s: %s (run athar verify for details)", f, p.Msg)
			}
		}
		c, _, err := eval.Compile(r)
		if err != nil {
			return nil, fmt.Errorf("%s: %v (run athar verify for details)", f, err)
		}
		rules = append(rules, r)
		compiled = append(compiled, c)
	}
	for path, problems := range rule.CheckSet(rules) {
		for _, p := range problems {
			if p.Severity == rule.Error {
				return nil, fmt.Errorf("%s: %s", path, p.Msg)
			}
		}
	}
	return compiled, nil
}

// wrapList joins the numbers with commas and breaks lines before width.
func wrapList(v []int, width int) string {
	var b strings.Builder
	line := 0
	for i, n := range v {
		s := strconv.Itoa(n)
		if i < len(v)-1 {
			s += ","
		}
		if line > 0 && line+len(s) > width {
			b.WriteByte('\n')
			line = 0
		}
		b.WriteString(s)
		line += len(s)
	}
	return b.String()
}
