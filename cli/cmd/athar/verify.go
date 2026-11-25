package main

import (
	"errors"
	"flag"
	"fmt"
	"io"

	"github.com/Athar-HQ/Athar/cli/internal/color"
	"github.com/Athar-HQ/Athar/cli/internal/eval"
	"github.com/Athar-HQ/Athar/cli/internal/rule"
)

type verifyReport struct {
	path     string
	problems []rule.Problem
	tests    []eval.TestResult
}

func (r *verifyReport) count(sev rule.Severity) int {
	n := 0
	for _, p := range r.problems {
		if p.Severity == sev {
			n++
		}
	}
	return n
}

func (r *verifyReport) passed() int {
	n := 0
	for _, t := range r.tests {
		if t.Passed {
			n++
		}
	}
	return n
}

func cmdVerify(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("verify", flag.ContinueOnError)
	fs.SetOutput(stderr)
	strict := fs.Bool("strict", false, "treat warnings as failures")
	quiet := fs.Bool("q", false, "only print rules with problems, and the summary")
	noColor := fs.Bool("no-color", false, "no colors (also set by the NO_COLOR environment variable)")
	fs.Usage = func() {
		fmt.Fprintln(stderr, "Usage: athar verify [-strict] [-q] [-no-color] <rule file or folder>...")
		fmt.Fprintln(stderr, "\nChecks every rule against the spec and runs its tests.")
		fmt.Fprintln(stderr, "Exit code 0: all good, 1: errors or failed tests, 2: usage or read error.")
		fmt.Fprintln(stderr)
		fs.PrintDefaults()
	}
	paths, err := parseFlags(fs, args)
	if err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return exitOK
		}
		return exitUsage
	}
	if len(paths) == 0 {
		fs.Usage()
		return exitUsage
	}
	c := color.For(stdout, *noColor)

	files, err := rule.Files(paths)
	if err != nil {
		fmt.Fprintln(stderr, "athar verify:", err)
		return exitUsage
	}
	if len(files) == 0 {
		fmt.Fprintln(stderr, "athar verify: no .yml or .yaml files found")
		return exitUsage
	}

	reports := make([]*verifyReport, 0, len(files))
	byPath := map[string]*verifyReport{}
	var rules []*rule.Rule
	for _, f := range files {
		rep := &verifyReport{path: f}
		reports = append(reports, rep)
		byPath[f] = rep

		r, err := rule.Load(f)
		if err != nil {
			rep.problems = append(rep.problems, rule.Problem{Severity: rule.Error, Msg: err.Error()})
			continue
		}
		rules = append(rules, r)
		rep.problems = append(rep.problems, rule.Check(r)...)

		c, warnings, err := eval.Compile(r)
		if err != nil {
			rep.problems = append(rep.problems, rule.Problem{Severity: rule.Error, Msg: err.Error()})
			continue
		}
		rep.problems = append(rep.problems, warnings...)
		rep.tests = c.RunTests()
	}
	for path, problems := range rule.CheckSet(rules) {
		byPath[path].problems = append(byPath[path].problems, problems...)
	}

	width := 0
	for _, rep := range reports {
		width = max(width, len(rep.path))
	}

	var nErr, nWarn, nTests, nPassed, nFailedRules int
	for _, rep := range reports {
		e, w, passed := rep.count(rule.Error), rep.count(rule.Warning), rep.passed()
		nErr += e
		nWarn += w
		nTests += len(rep.tests)
		nPassed += passed
		failed := e > 0 || passed < len(rep.tests) || (*strict && w > 0)
		if failed {
			nFailedRules++
		}
		if *quiet && e == 0 && w == 0 && passed == len(rep.tests) {
			continue
		}

		status := fmt.Sprintf("%d/%d tests passed", passed, len(rep.tests))
		if failed {
			status = c.Bold(c.Red("FAIL")) + "  " + status
		} else {
			status = c.Green(status)
		}
		fmt.Fprintf(stdout, "%s  %s\n", fmt.Sprintf("%-*s", width, rep.path), status)
		for _, p := range rep.problems {
			if p.Severity == rule.Error {
				fmt.Fprintf(stdout, "  %s %s\n", c.Red("error:"), p.Msg)
			}
		}
		for _, t := range rep.tests {
			if !t.Passed {
				fmt.Fprintf(stdout, "  %s %s\n", c.Red(fmt.Sprintf("test %q failed:", t.Name)), t.Detail)
			}
		}
		for _, p := range rep.problems {
			if p.Severity == rule.Warning {
				fmt.Fprintf(stdout, "  %s %s\n", c.Yellow("warning:"), p.Msg)
			}
		}
	}

	failedRules := fmt.Sprintf("%d failed", nFailedRules)
	if nFailedRules > 0 {
		failedRules = c.Bold(c.Red(failedRules))
	}
	fmt.Fprintf(stdout, "\n%s, %s; %d/%d tests passed; %s, %s\n",
		plural(len(reports), "rule"), failedRules, nPassed, nTests, plural(nErr, "error"), plural(nWarn, "warning"))
	if nFailedRules > 0 {
		return exitFindings
	}
	return exitOK
}

func plural(n int, word string) string {
	if n == 1 {
		return fmt.Sprintf("%d %s", n, word)
	}
	return fmt.Sprintf("%d %ss", n, word)
}
