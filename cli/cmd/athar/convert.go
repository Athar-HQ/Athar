package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/Athar-HQ/Athar/cli/internal/color"
	"github.com/Athar-HQ/Athar/cli/internal/convert"
)

func cmdConvert(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("convert", flag.ContinueOnError)
	fs.SetOutput(stderr)
	targets := fs.String("t", strings.Join(convert.Engines, ","), "engines or scanners, comma-separated")
	jsonOut := fs.Bool("json", false, "print one JSON object per rule and engine")
	outDir := fs.String("o", "", "write templates to this folder instead of printing them: Nuclei as <template id>.yaml,\nnse as athar.nse plus athar-rules/<rule>.lua")
	noColor := fs.Bool("no-color", false, "no colors (also set by the NO_COLOR environment variable)")
	fs.Usage = func() {
		fmt.Fprintln(stderr, "Usage: athar convert [-t targets] [-json] [-o folder] <rule file or folder>...")
		fmt.Fprintln(stderr, "\nTurns rules into search-engine queries, Nuclei templates and Nmap script data. Each result is labelled with its fidelity:")
		fmt.Fprintln(stderr, "  exact        same results as the scanner on the engine's data or the same response")
		fmt.Fprintln(stderr, "  approximate  same intent, looser operator (tokenised text, prefix as substring)")
		fmt.Fprintln(stderr, "  superset     parts the engine can't express were dropped; can only over-match")
		fmt.Fprintln(stderr, "  unsupported  nothing meaningful left")
		fmt.Fprintf(stderr, "\nEngines: %s (the default)\nScanners: %s\n\n", strings.Join(convert.Engines, ", "), strings.Join(convert.Scanners, ", "))
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
	for _, e := range append(append([]string{}, convert.Engines...), convert.Scanners...) {
		known[e] = true
	}
	templates, onlyTemplates := false, true
	for _, e := range strings.Split(*targets, ",") {
		e = strings.ToLower(strings.TrimSpace(e))
		if e == "" {
			continue
		}
		if !known[e] {
			return fail("unknown target %q (engines: %s; scanners: %s)", e, strings.Join(convert.Engines, ", "), strings.Join(convert.Scanners, ", "))
		}
		engines = append(engines, e)
		templates = templates || slices.Contains(convert.Scanners, e)
		onlyTemplates = onlyTemplates && slices.Contains(convert.Scanners, e)
	}
	if len(engines) == 0 {
		return fail("no targets given with -t")
	}
	if *outDir != "" && !templates {
		return fail("-o only applies to templates; add -t nuclei or -t nse")
	}
	if *outDir != "" {
		if err := os.MkdirAll(*outDir, 0o755); err != nil {
			return fail("%v", err)
		}
		// athar.nse reads the rules' data files from athar-rules next to it.
		if slices.Contains(engines, "nse") {
			if err := os.MkdirAll(filepath.Join(*outDir, convert.NSERulesDir), 0o755); err != nil {
				return fail("%v", err)
			}
			if err := os.WriteFile(filepath.Join(*outDir, "athar.nse"), []byte(convert.NSEScript), 0o644); err != nil {
				return fail("%v", err)
			}
		}
	}
	written := map[string]string{} // template file -> rule path

	compiled, err := loadRules(paths)
	if err != nil {
		return fail("%v", err)
	}

	c := color.For(stdout, *noColor)
	enc := json.NewEncoder(stdout)
	enc.SetEscapeHTML(false)
	// With only templates and no folder, stdout is the templates themselves,
	// so one rule can go straight into a file. Fidelity and notes are in
	// each template's header comment. "---" separates YAML documents and is
	// a comment in Lua.
	if onlyTemplates && *outDir == "" && !*jsonOut {
		first := true
		for _, cr := range compiled {
			for _, engine := range engines {
				res, err := convert.Convert(cr.Rule, engine)
				if err != nil {
					return fail("%s: %v", cr.Rule.Path, err)
				}
				if !first {
					fmt.Fprintln(stdout, "---")
				}
				first = false
				if res.Template == "" {
					mark := map[string]string{"nuclei": "#", "nse": "--"}[engine]
					fmt.Fprintf(stdout, "%s %s: %s, no %s template\n", mark, cr.Rule.Path, res.Fidelity, engine)
					for _, n := range res.Notes {
						fmt.Fprintf(stdout, "%s Note: %s\n", mark, n)
					}
					continue
				}
				fmt.Fprint(stdout, res.Template)
			}
		}
		return exitOK
	}
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
			file := ""
			if res.Template != "" && *outDir != "" {
				file = filepath.Join(*outDir, res.TemplateID+".yaml")
				if engine == "nse" {
					file = filepath.Join(*outDir, convert.NSERulesDir, res.TemplateID+".lua")
				}
				if other, dup := written[file]; dup {
					return fail("%s and %s both give the template %s; rename one of the rule files", other, r.Path, file)
				}
				written[file] = r.Path
				if err := os.WriteFile(file, []byte(res.Template), 0o644); err != nil {
					return fail("%v", err)
				}
			}
			if *jsonOut {
				if file != "" {
					res.Template = ""
				}
				enc.Encode(struct {
					Rule  string `json:"rule"`
					Path  string `json:"path"`
					Title string `json:"title"`
					convert.Result
					File string `json:"file,omitempty"`
				}{r.ID, r.Path, r.Title, res, file})
				continue
			}
			query := res.Query
			switch {
			case file != "":
				query = file
			case res.Template != "":
				query = c.Dim("template below")
			case query == "":
				query = c.Dim("—")
			}
			fmt.Fprintf(stdout, "  %s %s %s\n",
				c.Cyan(fmt.Sprintf("%-8s", engine)), fidelity(c, res.Fidelity), query)
			for _, n := range res.Notes {
				fmt.Fprintf(stdout, "  %s %s\n", strings.Repeat(" ", 8+1+12), c.Dim("note: "+n))
			}
			if res.Template != "" && file == "" {
				fmt.Fprintf(stdout, "\n%s\n", strings.TrimRight(res.Template, "\n"))
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
