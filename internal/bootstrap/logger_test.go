package bootstrap

import (
	"bytes"
	"log"
	"os"
	"strings"
	"testing"
)

func TestMapLogLevel(t *testing.T) {
	tests := []struct {
		input    string
		expected int
		wantErr  bool
	}{
		{"debug", 0, false},
		{"info", 1, false},
		{"notice", 2, false},
		{"warn", 3, false},
		{"error", 4, false},
		{"critical", 5, false},
		{"alert", 6, false},
		{"emergency", 7, false},
		{"unknown", 0, true},
	}
	for _, tt := range tests {
		lvl, err := mapLogLevel(tt.input)
		if (err != nil) != tt.wantErr {
			t.Errorf("mapLogLevel(%q) error = %v, wantErr %v", tt.input, err, tt.wantErr)
		}
		if lvl != tt.expected {
			t.Errorf("mapLogLevel(%q) = %d, want %d", tt.input, lvl, tt.expected)
		}
	}
}

func captureLogOutput(f func()) string {
	var buf bytes.Buffer
	// logger := log.New(&buf, "", 0)
	orig := log.Default()
	log.SetOutput(&buf)
	log.SetFlags(0)
	defer func() {
		log.SetOutput(os.Stderr)
		log.SetFlags(orig.Flags())
	}()
	f()
	return buf.String()
}

func TestConsoleLoggerLevels(t *testing.T) {
	logger, err := InitConsoleLogger("debug")
	if err != nil {
		t.Fatalf("InitConsoleLogger failed: %v", err)
	}
	tests := []struct {
		name     string
		logFunc  func(l *ConsoleLogger)
		wantText string
	}{
		{"Debug", func(l *ConsoleLogger) { l.Debug("debug msg", "k", 1) }, "[DEBUG] debug msg: [ k=1 ]"},
		{"Info", func(l *ConsoleLogger) { l.Info("info msg", "k", 2) }, "[INFO] info msg: [ k=2 ]"},
		{"Notice", func(l *ConsoleLogger) { l.Notice("notice msg", "k", 3) }, "[NOTICE] notice msg: [ k=3 ]"},
		{"Warn", func(l *ConsoleLogger) { l.Warn("warn msg", "k", 4) }, "[WARN] warn msg: [ k=4 ]"},
		{"Error", func(l *ConsoleLogger) { l.Error("error msg", "k", 5) }, "[ERROR] error msg: [ k=5 ]"},
		{"Critical", func(l *ConsoleLogger) { l.Critical("critical msg", "k", 6) }, "[CRITICAL] critical msg: [ k=6 ]"},
		{"Alert", func(l *ConsoleLogger) { l.Alert("alert msg", "k", 7) }, "[ALERT] alert msg: [ k=7 ]"},
	}
	for _, tt := range tests {
		out := captureLogOutput(func() { tt.logFunc(logger) })
		if !strings.Contains(out, tt.wantText) {
			t.Errorf("%s: log output = %q, want substring %q", tt.name, out, tt.wantText)
		}
	}
}

func TestConsoleLoggerLevelFiltering(t *testing.T) {
	logger, err := InitConsoleLogger("error")
	if err != nil {
		t.Fatalf("InitConsoleLogger failed: %v", err)
	}
	// Only Error, Critical, Alert, Emergency should log
	shouldLog := []struct {
		name    string
		logFunc func(l *ConsoleLogger)
		want    bool
	}{
		{"Debug", func(l *ConsoleLogger) { l.Debug("msg") }, false},
		{"Info", func(l *ConsoleLogger) { l.Info("msg") }, false},
		{"Notice", func(l *ConsoleLogger) { l.Notice("msg") }, false},
		{"Warn", func(l *ConsoleLogger) { l.Warn("msg") }, false},
		{"Error", func(l *ConsoleLogger) { l.Error("msg") }, true},
		{"Critical", func(l *ConsoleLogger) { l.Critical("msg") }, true},
		{"Alert", func(l *ConsoleLogger) { l.Alert("msg") }, true},
	}
	for _, tt := range shouldLog {
		out := captureLogOutput(func() { tt.logFunc(logger) })
		if (out != "") != tt.want {
			t.Errorf("%s: log output presence = %v, want %v", tt.name, out != "", tt.want)
		}
	}
}

func TestPrettyPrint(t *testing.T) {
	got := prettyPrint([]any{"foo", 123, "bar", "baz"})
	want := "[ foo=123  bar=baz ]"
	if got != want {
		t.Errorf("prettyPrint() = %q, want %q", got, want)
	}
	got2 := prettyPrint([]any{})
	if got2 != "[]" {
		t.Errorf("prettyPrint([]) = %q, want []", got2)
	}
}
