package http

import (
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// Foo is a sample struct for testing WriteJSON.
type Foo struct {
	Foo string `json:"foo"`
}

// errorWriter simulates a ResponseWriter that always fails on Write.
type errorWriter struct {
	header http.Header
}

func (e *errorWriter) Header() http.Header {
	if e.header == nil {
		e.header = make(http.Header)
	}
	return e.header
}

func (e *errorWriter) Write([]byte) (int, error) {
	return 0, errors.New("write failed")
}

func (e *errorWriter) WriteHeader(statusCode int) {}

// TestWriteJSON_Success verifies that on valid input, WriteJSON writes
// the correct header and body, and returns no error.
func TestWriteJSON_Success(t *testing.T) {
	rec := httptest.NewRecorder()
	src := Foo{Foo: "bar"}

	err := WriteJSON(rec, src)
	if err != nil {
		t.Fatalf("WriteJSON returned unexpected error: %v", err)
	}

	// Check Content-Type header
	if ct := rec.Header().Get("Content-Type"); ct != "application/json" {
		t.Errorf("wrong Content-Type: got %q, want %q", ct, "application/json")
	}

	// json.Encoder.Encode adds a trailing newline
	wantBody := `{"foo":"bar"}` + "\n"
	if body := rec.Body.String(); body != wantBody {
		t.Errorf("wrong body: got %q, want %q", body, wantBody)
	}
}

// TestWriteJSON_Error simulates a write failure and ensures
// WriteJSON returns an AppError with the correct fields.
func TestWriteJSON_Error(t *testing.T) {
	w := &errorWriter{}
	src := Foo{Foo: "bar"}

	appErr := WriteJSON(w, src)
	if appErr == nil {
		t.Fatal("expected error, got nil")
	}

	if appErr.Code != 500 {
		t.Errorf("wrong status code: got %d, want %d", appErr.Code, 500)
	}

	if appErr.Message != "Internal server error" {
		t.Errorf("wrong message: got %q, want %q", appErr.Message, "Internal server error")
	}

	if !strings.Contains(appErr.Err.Error(), "write failed") {
		t.Errorf("underlying error = %q; want it to contain %q", appErr.Err.Error(), "write failed")
	}
}

// TestWriteJSON_Repeated runs the success case multiple times
// to catch any intermittent issues.
func TestWriteJSON_Repeated(t *testing.T) {
	const iterations = 10
	for i := 0; i < iterations; i++ {
		i := i // capture
		t.Run(fmt.Sprintf("iteration_%02d", i+1), func(t *testing.T) {
			rec := httptest.NewRecorder()
			src := Foo{Foo: "bar"}

			if err := WriteJSON(rec, src); err != nil {
				t.Fatalf("iteration %d: unexpected error: %v", i+1, err)
			}
			if ct := rec.Header().Get("Content-Type"); ct != "application/json" {
				t.Errorf("iteration %d: wrong Content-Type: got %q", i+1, ct)
			}
			wantBody := `{"foo":"bar"}` + "\n"
			if body := rec.Body.String(); body != wantBody {
				t.Errorf("iteration %d: wrong body: got %q", i+1, body)
			}
		})
	}
}
