package encryption

import (
	"errors"
	"kms/internal/test/mocks"
	"kms/pkg/encryption"
	kmsErrors "kms/pkg/errors"
	"strings"
	"testing"
)

func TestString_Roundtrip_Success(t *testing.T) {
	secret, err := encryption.GenerateKey(32)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	original := "Unencrypted"
	enc, err := EncryptString(original, secret)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	dec, err := DecryptString(enc, secret)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if dec != original {
		t.Errorf("expected %s, got %s", original, dec)
	}
}

func TestString_Decrypt_NonB64Error(t *testing.T) {
	secret, err := encryption.GenerateKey(32)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	_, err = DecryptString("not+base64", secret)
	if err == nil {
		t.Fatalf("expected error")
	}
}

func TestBase64_Encrypt_NonB64Error(t *testing.T) {
	secret, err := encryption.GenerateKey(32)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	_, err = EncryptBase64("not+base64", secret)
	if err == nil {
		t.Fatalf("expected error")
	}
}

type Foo struct {
	Client string `encrypt:"true"`
	Id     int
	Ref    string `encoded:"true" encrypt:"true"`
}

func (f *Foo) Equals(fc *Foo) bool {
	return f.Id == fc.Id && f.Client == fc.Client && f.Ref == fc.Ref
}

func TestFields_Roundtrip_Success(t *testing.T) {
	dbKey, err := encryption.GenerateKey(32)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	kek, err := encryption.GenerateKey(32)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	keyManager := mocks.NewKeyManagerMock()
	keyManager.DBKeyFunc = func() []byte {
		return dbKey
	}
	keyManager.KEKFunc = func() []byte {
		return kek
	}

	original := &Foo{
		Client: "Client",
		Id:     1,
		Ref:    "cmVmZXJlbmNl", // "Reference" in base64
	}
	enc := &Foo{}

	err = EncryptFields(enc, original, keyManager)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Check if ID is left unencrypted
	if enc.Id != original.Id {
		t.Errorf("expected ID '%v', got %v", original.Id, enc.Id)
	}

	// Check if other fields are actually encrypted
	if enc.Client == original.Client || enc.Ref == original.Ref {
		t.Errorf("expected client and reference to be different, got client: %v, ref: %v", enc.Client, enc.Ref)
	}

	dec := &Foo{}
	err = DecryptFields(dec, enc, keyManager)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !original.Equals(dec) {
		t.Errorf("expected %v, got %v", original, dec)
	}
}

func TestEncryptFields_InvalidInput(t *testing.T) {
	dbKey, err := encryption.GenerateKey(32)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	kek, err := encryption.GenerateKey(32)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	keyManager := mocks.NewKeyManagerMock()
	keyManager.DBKeyFunc = func() []byte {
		return dbKey
	}
	keyManager.KEKFunc = func() []byte {
		return kek
	}

	tests := []struct {
		name     string
		dst      any
		src      any
		expected string
	}{
		{"non-pointer", Foo{}, Foo{}, "src and dst must be pointers"},
		{"*int", new(int), new(int), "src and dst must point to structs"},
		{"*string", new(string), new(string), "src and dst must point to structs"},
		{"*[]byte", new([]byte), new([]byte), "src and dst must point to structs"},
		{"*map[string]int", new(map[string]int), new(map[string]int), "src and dst must point to structs"},
		{"*interface{}", new(interface{}), new(interface{}), "src and dst must point to structs"},
		{"**Foo", new(*Foo), new(*Foo), "src and dst must point to structs"},
		{"different structs", &Foo{}, &struct{}{}, "src and dst must be the same struct type"},
		{"unable to set field", &struct{ client string }{}, &struct{ client string }{client: "client"}, "Unable to set field"},
		{"non-string", &struct {
			ID int `encrypt:"true"`
		}{}, &struct {
			ID int `encrypt:"true"`
		}{ID: 1}, "Field marked for encryption but is not a string"},
		{"invalid base64", &struct {
			Client string `encrypt:"true" encoded:"true"`
		}{}, &struct {
			Client string `encrypt:"true" encoded:"true"`
		}{Client: "not+base64"}, "Failed to decode field"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := EncryptFields(tt.dst, tt.src, keyManager)
			if err == nil {
				t.Fatalf("expected error for %s, got nil", tt.name)
			}
			if !errors.Is(err, kmsErrors.ErrRepoEncryption) {
				t.Fatalf("expected repo encryption error, got %v", err)
			}
			if !strings.Contains(err.Error(), tt.expected) {
				t.Errorf("expected '%s', got '%s'", tt.expected, err.Error())
			}
		})
	}
}

func TestDecryptFields_InvalidInput(t *testing.T) {
	dbKey, err := encryption.GenerateKey(32)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	kek, err := encryption.GenerateKey(32)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	keyManager := mocks.NewKeyManagerMock()
	keyManager.DBKeyFunc = func() []byte {
		return dbKey
	}
	keyManager.KEKFunc = func() []byte {
		return kek
	}

	tests := []struct {
		name     string
		dst      any
		src      any
		expected string
	}{
		{"non-pointer", Foo{}, Foo{}, "src and dst must be pointers"},
		{"*int", new(int), new(int), "src and dst must point to structs"},
		{"*string", new(string), new(string), "src and dst must point to structs"},
		{"*[]byte", new([]byte), new([]byte), "src and dst must point to structs"},
		{"*map[string]int", new(map[string]int), new(map[string]int), "src and dst must point to structs"},
		{"*interface{}", new(interface{}), new(interface{}), "src and dst must point to structs"},
		{"**Foo", new(*Foo), new(*Foo), "src and dst must point to structs"},
		{"different structs", &Foo{}, &struct{}{}, "src and dst must be the same struct type"},
		{"unable to set field", &struct{ client string }{}, &struct{ client string }{client: "client"}, "Unable to set field"},
		{"non-string", &struct {
			ID int `encrypt:"true"`
		}{}, &struct {
			ID int `encrypt:"true"`
		}{ID: 1}, "Field marked for decryption but is not a string"},
		{"invalid base64", &struct {
			Client string `encrypt:"true" encoded:"true"`
		}{}, &struct {
			Client string `encrypt:"true" encoded:"true"`
		}{Client: "not+base64"}, "Failed to decode field"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := DecryptFields(tt.dst, tt.src, keyManager)
			if err == nil {
				t.Fatalf("expected error for %s, got nil", tt.name)
			}
			if !errors.Is(err, kmsErrors.ErrRepoEncryption) {
				t.Fatalf("expected repo encryption error, got %v", err)
			}
			if !strings.Contains(err.Error(), tt.expected) {
				t.Errorf("expected '%s', got '%s'", tt.expected, err.Error())
			}
		})
	}
}
