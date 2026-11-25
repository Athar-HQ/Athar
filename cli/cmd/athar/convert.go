package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"strings"

	"github.com/Athar-HQ/Athar/cli/internal/color"
	"github.com/Athar-HQ/Athar/cli/internal/convert"
)

func cmdConvert(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("convert", flag.ContinueOnError)
	fs.SetOutput(stderr)
	targets := fs.String("t", strings.Join(convert.Engines, ","), "engines, comma-separated")
	jsonOut := fs.Bool("json", false, "print one JSON object per rule and engine")
	noColor := fs.Bool("no-color", false, "no colors (also set by the NO_COLOR environment variable)")
	fs.Usage = func() {
		fmt.Fprintln(stderr, "Usage: athar convert [-t engines] [-json] <rule file or folder>...")
		fmt.Fprintln(stderr, "\nTurns rules into search-engine queries. Each query is labelled with its fidelity:")
		fmt.Fprintln(stderr, "  exact        same results as the scanner on the engine's data")
		fmt.Fprintln(stderr, "  approximate  same intent, looser operator (tokenised text, prefix as substring)")
		fmt.Fprintln(stderr, "  superset     parts the engine can't express were dropped; can only over-match")
		fmt.Fprintln(stderr, "  unsupported  nothing meaningful left")
		fmt.Fprintf(stderr, "\nEngines: %s\n\n", strings.Join(convert.Engines, ", "))
		fs.PrintDefaults()
	}
	paths, err := parseFlags(fs, args)
	if err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return exitOK
		}
		return exitUsage
	}
	fail := func(format string, a ...any) int {
		fmt.Fprintf(stderr, "athar convert: "+format+"\n", a...)
		return exitUsage
	}
	if len(paths) == 0 {
		fs.Usage()
		return exitUsage
	}

	var engines []string
	known := map[string]bool{}
	for _, e := range convert.Engines {
		known[e] = true
	}
	for _, e := range strings.Split(*targets, ",") {
		e = strings.ToLower(strings.TrimSpace(e))
		if e == "" {
			continue
		}
		if !known[e] {
			return fail("unknown engine %q (supported: %s)", e, strings.Join(convert.Engines, ", "))
		}
		engines = append(engines, e)
	}
	if len(engines) == 0 {
		return fail("no engines given with -t")
	}

	compiled, err := loadRules(paths)
	if err != nil {
		return fail("%v", err)
	}

	c := color.For(stdout, *noColor)
	enc := json.NewEncoder(stdout)
	enc.SetEscapeHTML(false)
	for i, cr := range compiled {
		r := cr.Rule
		if !*jsonOut {
			if i > 0 {
				fmt.Fprintln(stdout)
			}
			fmt.Fprintf(stdout, "%s  %s\n", c.Bold(r.Title), c.Dim(r.Path))
		}
		for _, engine := range engines {
			res, err := convert.Convert(r, engine)
			if err != nil {
				return fail("%s: %v", r.Path, err)
			}
			if *jsonOut {
				enc.Encode(struct {
					Rule  string `json:"rule"`
					Path  string `json:"path"`
					Title string `json:"title"`
					convert.Result
				}{r.ID, r.Path, r.Title, res})
				continue
			}
			query := res.Query
			if query == "" {
				query = c.Dim("—")
			}
			fmt.Fprintf(stdout, "  %s %s %s\n",
				c.Cyan(fmt.Sprintf("%-8s", engine)), fidelity(c, res.Fidelity), query)
			for _, n := range res.Notes {
				fmt.Fprintf(stdout, "  %s %s\n", strings.Repeat(" ", 8+1+12), c.Dim("note: "+n))
			}
		}
	}
	return exitOK
}

func fidelity(c color.Palette, f convert.Fidelity) string {
	s := fmt.Sprintf("%-12s", f)
	switch f {
	case convert.Exact:
		return c.Green(s)
	case convert.Approximate:
		return c.Yellow(s)
	case convert.Superset:
		return c.Magenta(s)
	}
	return c.Red(s)
}
