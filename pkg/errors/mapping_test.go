package errors

import (
	"database/sql"
	"errors"
	"testing"

	"github.com/lib/pq"
	"golang.org/x/crypto/bcrypt"
)

func TestMapRepoErr(t *testing.T) {
	tests := []struct {
		name        string
		input       error
		wantCode    int
		wantMessage string
	}{
		{"sql.ErrNoRows", sql.ErrNoRows, 404, "Entity not found"},
		{"ErrNoRowsAffected", ErrNoRowsAffected, 404, "Entity not found"},
		{"unique constraint", &pq.Error{Code: "23505"}, 409, "Resource already exists"},
		{"fk violation", &pq.Error{Code: "23503"}, 400, "Invalid foreign key"},
		{"not null violation", &pq.Error{Code: "23502"}, 400, "Missing required value"},
		{"input too long", &pq.Error{Code: "22001"}, 400, "Value too long"},
		{"undefined column", &pq.Error{Code: "42703"}, 500, "Internal server error"},
		{"undefined table", &pq.Error{Code: "42P01"}, 500, "Internal server error"},
		{"syntax error", &pq.Error{Code: "42601"}, 500, "Internal server error"},
		{"other error", errors.New("boom"), 500, "Internal server error"},
	}

	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			appErr := MapRepoErr(tc.input)
			if appErr.Code != tc.wantCode {
				t.Errorf("MapRepoErr(%v).Code = %d; want %d", tc.input, appErr.Code, tc.wantCode)
			}
			if appErr.Message != tc.wantMessage {
				t.Errorf("MapRepoErr(%v).Message = %q; want %q", tc.input, appErr.Message, tc.wantMessage)
			}
			if appErr.Err != tc.input {
				t.Errorf("MapRepoErr(%v).Err = %v; want %v", tc.input, appErr.Err, tc.input)
			}
		})
	}
}

func TestMapHashErr(t *testing.T) {
	tests := []struct {
		name        string
		input       error
		wantCode    int
		wantMessage string
	}{
		{"mismatched hash", bcrypt.ErrMismatchedHashAndPassword, 401, "Incorrect clientname or password"},
		{"other error", errors.New("boom"), 500, "Internal server error"},
	}

	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			appErr := MapHashErr(tc.input)
			if appErr.Code != tc.wantCode {
				t.Errorf("MapHashErr(%v).Code = %d; want %d", tc.input, appErr.Code, tc.wantCode)
			}
			if appErr.Message != tc.wantMessage {
				t.Errorf("MapHashErr(%v).Message = %q; want %q", tc.input, appErr.Message, tc.wantMessage)
			}
			if appErr.Err != tc.input {
				t.Errorf("MapHashErr(%v).Err = %v; want %v", tc.input, appErr.Err, tc.input)
			}
		})
	}
}

func TestMapVerifyTokenErr(t *testing.T) {
	tests := []struct {
		name        string
		input       error
		wantCode    int
		wantMessage string
	}{
		{"invalid token", ErrInvalidToken, 401, "Unauthorized"},
		{"other error", errors.New("boom"), 500, "Internal server error"},
	}

	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			appErr := MapVerifyTokenErr(tc.input)
			if appErr.Code != tc.wantCode {
				t.Errorf("MapVerifyTokenErr(%v).Code = %d; want %d", tc.input, appErr.Code, tc.wantCode)
			}
			if appErr.Message != tc.wantMessage {
				t.Errorf("MapVerifyTokenErr(%v).Message = %q; want %q", tc.input, appErr.Message, tc.wantMessage)
			}
			if appErr.Err != tc.input {
				t.Errorf("MapVerifyTokenErr(%v).Err = %v; want %v", tc.input, appErr.Err, tc.input)
			}
		})
	}
}
