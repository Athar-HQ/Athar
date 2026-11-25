// Package color adds ANSI colors to terminal output. Colors are used only
// when the output is a terminal, NO_COLOR is not set, and the user did not
// turn them off.
package color

import (
	"io"
	"os"
	"runtime"
)

// Palette wraps strings in ANSI color codes, or returns them unchanged when
// colors are off.
type Palette struct{ on bool }

// New returns a palette that colors when on is true.
func New(on bool) Palette { return Palette{on: on} }

// For returns a palette for w: colors only if w is a terminal that supports
// them, the NO_COLOR environment variable is unset (https://no-color.org),
// and disable is false.
func For(w io.Writer, disable bool) Palette {
	f, ok := w.(*os.File)
	return Palette{on: ok && !disable && os.Getenv("NO_COLOR") == "" && isTerminal(f) && supported()}
}

// On reports whether the palette colors.
func (p Palette) On() bool { return p.on }

func (p Palette) wrap(code, s string) string {
	if !p.on || s == "" {
		return s
	}
	return "\x1b[" + code + "m" + s + "\x1b[0m"
}

func (p Palette) Bold(s string) string    { return p.wrap("1", s) }
func (p Palette) Dim(s string) string     { return p.wrap("2", s) }
func (p Palette) Red(s string) string     { return p.wrap("31", s) }
func (p Palette) Green(s string) string   { return p.wrap("32", s) }
func (p Palette) Yellow(s string) string  { return p.wrap("33", s) }
func (p Palette) Magenta(s string) string { return p.wrap("35", s) }
func (p Palette) Cyan(s string) string    { return p.wrap("36", s) }

// isTerminal reports whether f is a character device, which is how
// terminals appear on Unix and on Windows consoles.
func isTerminal(f *os.File) bool {
	info, err := f.Stat()
	return err == nil && info.Mode()&os.ModeCharDevice != 0
}

// supported is false for classic Windows consoles, which print escape codes
// literally. Windows Terminal (WT_SESSION) and terminals that set TERM
// handle them.
func supported() bool {
	if runtime.GOOS != "windows" {
		return true
	}
	return os.Getenv("WT_SESSION") != "" || os.Getenv("TERM") != ""
}
