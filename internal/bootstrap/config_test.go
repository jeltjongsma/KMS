package bootstrap

import (
	"errors"
	"os"
	"strings"
	"testing"
)

func writeTempFile(t *testing.T, content string) string {
	t.Helper()
	f, err := os.CreateTemp("", "kmsconfig-*.env")
	if err != nil {
		t.Fatalf("failed to create temp file: %v", err)
	}
	if _, err := f.WriteString(content); err != nil {
		f.Close()
		t.Fatalf("failed to write temp file: %v", err)
	}
	f.Close()
	return f.Name()
}

func TestLoadConfig_Valid(t *testing.T) {
	content := `
    # comment line
    JWT_SECRET = foo
    SIGNUP_SECRET=bar
    # another comment
    KEK = baz
    `
	fname := writeTempFile(t, content)
	defer os.Remove(fname)
	cfg, err := LoadConfig(fname)
	if err != nil {
		t.Fatalf("LoadConfig failed: %v", err)
	}
	if cfg["JWT_SECRET"] != "foo" || cfg["SIGNUP_SECRET"] != "bar" || cfg["KEK"] != "baz" {
		t.Errorf("unexpected config: %#v", cfg)
	}
}

func TestLoadConfig_BlankAndCommentLines(t *testing.T) {
	content := "\n\n# comment\nFOO=bar\n\n# another\nBAZ=qux\n"
	fname := writeTempFile(t, content)
	defer os.Remove(fname)
	cfg, err := LoadConfig(fname)
	if err != nil {
		t.Fatalf("LoadConfig failed: %v", err)
	}
	if len(cfg) != 2 || cfg["FOO"] != "bar" || cfg["BAZ"] != "qux" {
		t.Errorf("unexpected config: %#v", cfg)
	}
}

func TestLoadConfig_InvalidFormat(t *testing.T) {
	content := "FOO=bar\nBADLINE\nBAZ=qux"
	fname := writeTempFile(t, content)
	defer os.Remove(fname)
	_, err := LoadConfig(fname)
	if err == nil || !strings.Contains(err.Error(), "invalid format") {
		t.Errorf("expected invalid format error, got: %v", err)
	}
}

func TestLoadConfig_EmptyKeyOrValue(t *testing.T) {
	content := "FOO=bar\n=novalue\nkeyonly=\nBAZ=qux"
	fname := writeTempFile(t, content)
	defer os.Remove(fname)
	_, err := LoadConfig(fname)
	if err == nil || !strings.Contains(err.Error(), "invalid key or value") {
		t.Errorf("expected invalid key or value error, got: %v", err)
	}
}

func TestLoadConfig_FileNotFound(t *testing.T) {
	_, err := LoadConfig("/no/such/file/shouldexist.env")
	if err == nil {
		t.Error("expected error for missing file, got nil")
	}
	if !errors.Is(err, os.ErrNotExist) {
		t.Errorf("expected os.ErrNotExist, got: %v", err)
	}
}
