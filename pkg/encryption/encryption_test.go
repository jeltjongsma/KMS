package encryption

import (
	"bytes"
	"math/rand"
	"testing"
	"time"
)

func TestEncryptionRoundtrip(t *testing.T) {
	key, err := GenerateKey(32)
	if err != nil {
		t.Fatalf("generate key failed: %v", err)
	}

	for i := 0; i < 10; i++ {
		want := randomBytes(32 + i*7)

		encrypted, err := Encrypt(want, key)
		if err != nil {
			t.Fatalf("encryption failed: %v", err)
		}

		decrypted, err := Decrypt(encrypted, key)
		if err != nil {
			t.Fatalf("decryption failed: %v", err)
		}

		if !bytes.Equal(want, decrypted) {
			t.Errorf("roundtrip failed: got %q; want %q", decrypted, want)
		}
	}
}

func TestGenerateKey(t *testing.T) {
	plaintext := randomBytes(2139)

	for i := 0; i < 10; i++ {
		key, err := GenerateKey(32)
		if err != nil {
			t.Errorf("generate key failed: %v", err)
		}

		encrypted, err := Encrypt(plaintext, key)
		if err != nil {
			t.Fatalf("encryption failed: %v", err)
		}

		decrypted, err := Decrypt(encrypted, key)
		if err != nil {
			t.Fatalf("decryption failed: %v", err)
		}

		if !bytes.Equal(plaintext, decrypted) {
			t.Errorf("roundtrip failed: got %q; want %q", decrypted, plaintext)
		}
	}
}

func randomBytes(n int) []byte {
	rand.Seed(time.Now().UnixNano())
	b := make([]byte, n)
	for i := range b {
		b[i] = byte(rand.Intn(256))
	}
	return b
}
