// Command athar verifies, converts and evaluates Athar service fingerprint
// rules, and scans live services for them.
package main

import (
	"fmt"
	"io"
	"os"
)

// version is set at build time with -ldflags "-X main.version=...".
var version = "dev"

// Exit codes.
const (
	exitOK       = 0
	exitFindings = 1 // rule errors, failed tests, or warnings with -strict
	exitUsage    = 2 // bad arguments, unreadable input, not implemented
)

const usage = `athar: Athar service fingerprint rules

Usage:
  athar <command> [flags] [arguments]

Commands:
  verify    check rule syntax and run every rule's tests
  convert   turn rules into search-engine queries (not implemented yet)
  match     evaluate rules against stored data (not implemented yet)
  scan      probe live services (not implemented yet)
  version   print the version

Run "athar <command> -h" for a command's flags.
`

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
	case "convert", "match", "scan":
		fmt.Fprintf(stderr, "athar %s: not implemented yet, see cli/README.md\n", cmd)
		return exitUsage
	case "version", "-version", "--version":
		fmt.Fprintln(stdout, "athar", version)
		return exitOK
	case "help", "-h", "-help", "--help":
		fmt.Fprint(stdout, usage)
		return exitOK
	default:
		fmt.Fprintf(stderr, "athar: unknown command %q\n\n%s", cmd, usage)
		return exitUsage
	}
}
