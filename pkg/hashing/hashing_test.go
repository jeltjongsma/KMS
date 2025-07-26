package hashing

import (
	"encoding/base64"
	"testing"
)

func TestHashPassword(t *testing.T) {
	test := "securepassword21"
	got, err := HashPassword(test)
	if err != nil {
		t.Errorf("failed to hash password: %s", test)
	}
	if got == test {
		t.Errorf("password and hash are equal: got %s; input %s", got, test)
	}
	if len(got) != 60 {
		t.Errorf("expected bcrypt hash to be 60 characters, but is: %d", len(got))
	}
}

func TestCheckPassword(t *testing.T) {
	test := "securepassword21"
	hashed, err := HashPassword(test)
	if err != nil {
		t.Fatalf("failed to hash password: %s", test)
	}
	if err := CheckPassword(hashed, test); err != nil {
		t.Errorf("expected hashes to match but got: %v", err)
	}
}

func TestHashHS256ToB64(t *testing.T) {
	tests := []struct {
		name        string
		plain       []byte
		secret      []byte
		expectedLen int // HMAC-SHA256 always produces 32 bytes → Base64-URL encoded = 43 characters
	}{
		{
			name:        "basic case",
			plain:       []byte("hello"),
			secret:      []byte("mysecret"),
			expectedLen: 43,
		},
		{
			name:        "empty input",
			plain:       []byte(""),
			secret:      []byte("secret"),
			expectedLen: 43,
		},
		{
			name:        "empty secret",
			plain:       []byte("data"),
			secret:      []byte(""),
			expectedLen: 43,
		},
		{
			name:        "both empty",
			plain:       []byte(""),
			secret:      []byte(""),
			expectedLen: 43,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := HashHS256ToB64(tt.plain, tt.secret)

			// Check length
			if len(got) != tt.expectedLen {
				t.Errorf("unexpected hash length: got %d, want %d", len(got), tt.expectedLen)
			}

			// Check that it's valid base64url
			_, err := base64.RawURLEncoding.DecodeString(got)
			if err != nil {
				t.Errorf("output is not valid base64url: %v", err)
			}
		})
	}
}
