package test

import (
	"strings"
	"testing"
)

func RequireErrNil(t *testing.T, err error) {
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func RequireErrNotNil(t *testing.T, err error) {
	if err == nil {
		t.Fatal("expected error, got nil")
	}
}

func RequireErrContains(t *testing.T, err error, expected string) {
	if !strings.Contains(err.Error(), expected) {
		t.Errorf("expected %s, got %v", expected, err)
	}
}

func RequireContains(t *testing.T, msg string, expected string) {
	if !strings.Contains(msg, expected) {
		t.Fatalf("expected to contain %s, got %s", expected, msg)
	}
}
