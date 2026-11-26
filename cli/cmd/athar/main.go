// Command athar verifies, converts and evaluates Athar service fingerprint
// rules, and scans live services for them.
package main

import (
	"flag"
	"fmt"
	"io"
	"os"
	"runtime/debug"
)

// version is set by release builds with -ldflags "-X main.version=v1.2.3".
var version = ""

// versionString returns the release version, else the module version Go
// recorded at build time (e.g. for "go install ...@v1.2.3"), else "dev".
func versionString() string {
	if version != "" {
		return version
	}
	if bi, ok := debug.ReadBuildInfo(); ok && bi.Main.Version != "" && bi.Main.Version != "(devel)" {
		return bi.Main.Version
	}
	return "dev"
}

// Exit codes.
const (
	exitOK       = 0
	exitFindings = 1 // rule errors, failed tests, or warnings with -strict
	exitUsage    = 2 // bad arguments, unreadable input, invalid rules, not implemented
)

const usage = `athar: Athar service fingerprint rules

Usage:
  athar <command> [flags] [arguments]

Commands:
  scan      check hosts, ranges and ports for services that match the rules
  verify    check rule syntax and run every rule's tests
  convert   turn rules into search-engine queries, Nuclei templates and Nmap script data
  match     evaluate rules against stored data (not implemented yet)
  version   print the version

Run "athar <command> -h" for a command's flags.
`

// parseFlags parses flags that may come before, between or after the
// positional arguments, as Nmap allows, and returns the positional ones.
// Everything after "--" is positional.
func parseFlags(fs *flag.FlagSet, args []string) ([]string, error) {
	var pos []string
	for {
		if err := fs.Parse(args); err != nil {
			return nil, err
		}
		rest := fs.Args()
		// Parse stops after "--" and before a positional argument.
		if n := len(args) - len(rest); n > 0 && args[n-1] == "--" {
			return append(pos, rest...), nil
		}
		if len(rest) == 0 {
			return pos, nil
		}
		pos = append(pos, rest[0])
		args = rest[1:]
	}
}

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

func run(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprint(stderr, usage)
		return exitUsage
	}
	switch cmd := args[0]; cmd {
	case "verify":
		return cmdVerify(args[1:], stdout, stderr)
	case "scan":
		return cmdScan(args[1:], stdout, stderr)
	case "convert":
		return cmdConvert(args[1:], stdout, stderr)
	case "match":
		fmt.Fprintf(stderr, "athar %s: not implemented yet, see cli/README.md\n", cmd)
		return exitUsage
	case "version", "-version", "--version":
		fmt.Fprintln(stdout, "athar", versionString())
		return exitOK
	case "help", "-h", "-help", "--help":
		fmt.Fprint(stdout, usage)
		return exitOK
	default:
		fmt.Fprintf(stderr, "athar: unknown command %q\n\n%s", cmd, usage)
		return exitUsage
	}
}
