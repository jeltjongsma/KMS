package json

import (
	"bytes"
	"fmt"
	"testing"
)

// mockReadCloser wraps a bytes.Reader and records whether Close() was called.
type mockReadCloser struct {
	*bytes.Reader
	closed bool
}

func (m *mockReadCloser) Close() error {
	m.closed = true
	return nil
}

// Foo is a sample struct for testing ParseBody.
type Foo struct {
	Foo string `json:"foo"`
}

func TestParseBody(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		newDst  func() interface{}
		wantErr bool
	}{
		{
			name:  "valid JSON",
			input: `{"foo":"bar"}`,
			newDst: func() interface{} {
				return &Foo{}
			},
			wantErr: false,
		},
		{
			name:  "invalid JSON syntax",
			input: `{"foo":bar}`,
			newDst: func() interface{} {
				return &Foo{}
			},
			wantErr: true,
		},
		{
			name:  "unknown field",
			input: `{"foo":"bar","extra":123}`,
			newDst: func() interface{} {
				return &Foo{}
			},
			wantErr: true,
		},
		{
			name:  "dst not a pointer",
			input: `{"foo":"bar"}`,
			newDst: func() interface{} {
				// passing a non-pointer should cause Decode to error
				return Foo{}
			},
			wantErr: true,
		},
	}

	for _, tc := range tests {
		tc := tc // capture range variable
		t.Run(tc.name, func(t *testing.T) {
			// prepare a fresh ReadCloser for each run
			rc := &mockReadCloser{Reader: bytes.NewReader([]byte(tc.input))}
			dst := tc.newDst()

			err := ParseBody(rc, dst)

			// check error expectation
			if (err != nil) != tc.wantErr {
				t.Fatalf("ParseBody() error = %v, wantErr %v", err, tc.wantErr)
			}

			// ensure body.Close() was called
			if !rc.closed {
				t.Errorf("body.Close() was not called")
			}

			// on success, verify that dst was populated correctly
			if !tc.wantErr {
				foo, ok := dst.(*Foo)
				if !ok {
					t.Fatalf("dst has wrong type: got %T", dst)
				}
				if foo.Foo != "bar" {
					t.Errorf("parsed Foo.Foo = %q; want %q", foo.Foo, "bar")
				}
			}
		})
	}
}

// Additionally, test that extra JSON values after a valid object produce an error
func TestParseBody_ExtraJSON(t *testing.T) {
	input := `{"foo":"bar"}{"foo":"baz"}`
	rc := &mockReadCloser{Reader: bytes.NewReader([]byte(input))}
	dst := &Foo{}

	err := ParseBody(rc, dst)
	if err == nil {
		t.Fatal("expected error due to extra JSON after object, got nil")
	}
	if !rc.closed {
		t.Error("body.Close() was not called")
	}
}

// And finally, a simple fuzz-like repetition to catch flakiness
func TestParseBody_Repeated(t *testing.T) {
	const iterations = 10
	for i := 0; i < iterations; i++ {
		t.Run(fmt.Sprintf("repeat_%02d", i+1), func(t *testing.T) {
			rc := &mockReadCloser{Reader: bytes.NewReader([]byte(`{"foo":"bar"}`))}
			dst := &Foo{}
			if err := ParseBody(rc, dst); err != nil {
				t.Fatalf("iteration %d: unexpected error: %v", i+1, err)
			}
			if !rc.closed {
				t.Errorf("iteration %d: body.Close() was not called", i+1)
			}
			if dst.Foo != "bar" {
				t.Errorf("iteration %d: parsed Foo = %q; want %q", i+1, dst.Foo, "bar")
			}
		})
	}
}
