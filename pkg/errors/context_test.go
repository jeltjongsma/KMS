package errors

import (
	"errors"
	"kms/internal/test"
	"testing"
)

func TestWrapError(t *testing.T) {
	err := WrapError(errors.New("error"), map[string]any{
		"msg": "message",
	})
	test.RequireErrContains(t, err, "error")
	test.RequireErrContains(t, err, "map[msg:message]")
}

func TestLiftToAppError(t *testing.T) {
	err := LiftToAppError(errors.New("error"))
	if err.Code != 500 {
		t.Errorf("expected 500, got %d", err.Code)
	}
	if err.Err.Error() != "error" {
		t.Errorf("expected error, got %v", err.Err.Error())
	}
	if err.Message != "An error occurred" {
		t.Errorf("expected 'An error occurred', got %s", err.Message)
	}
}

func TestNewInternalServerError(t *testing.T) {
	err := NewInternalServerError(errors.New("error"))
	if err.Code != 500 {
		t.Errorf("expected 500, got %d", err.Code)
	}
	if err.Err.Error() != "error" {
		t.Errorf("expected error, got %v", err.Err.Error())
	}
	if err.Message != "Internal server error" {
		t.Errorf("expected 'Internal server error', got %s", err.Message)
	}
}

func TestNewInvalidBodyError(t *testing.T) {
	err := NewInvalidBodyError(errors.New("error"))
	if err.Code != 400 {
		t.Errorf("expected 400, got %d", err.Code)
	}
	if err.Err.Error() != "error" {
		t.Errorf("expected error, got %v", err.Err.Error())
	}
	if err.Message != "Invalid request body" {
		t.Errorf("expected 'Invalid request body', got %s", err.Message)
	}
}

func TestNewMissingCredentialsError(t *testing.T) {
	err := NewMissingCredentialsError(errors.New("error"))
	if err.Code != 400 {
		t.Errorf("expected 400, got %d", err.Code)
	}
	if err.Err.Error() != "error" {
		t.Errorf("expected error, got %v", err.Err.Error())
	}
	if err.Message != "Missing credentials" {
		t.Errorf("expected 'Missing credentials', got %s", err.Message)
	}
}
