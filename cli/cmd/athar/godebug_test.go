package main

import (
	"runtime/debug"
	"strings"
	"testing"
)

// The //go:debug line in main.go must reach the binary: without it a TLS
// service whose certificate has a negative serial number can't be read.
func TestNegativeSerialSetting(t *testing.T) {
	bi, _ := debug.ReadBuildInfo()
	for _, s := range bi.Settings {
		if s.Key == "DefaultGODEBUG" && strings.Contains(s.Value, "x509negativeserial=1") {
			return
		}
	}
	t.Error("x509negativeserial=1 is not among the binary's GODEBUG defaults")
}
