package bootstrap

import (
	"encoding/base64"
	c "kms/internal/bootstrap/context"
	"testing"
)

func mustB64(s string) string {
	return base64.RawURLEncoding.EncodeToString([]byte(s))
}

func TestInitStaticKeyManager_Success(t *testing.T) {
	cfg := c.KmsConfig{
		"JWT_SECRET":      mustB64("jwt"),
		"SIGNUP_SECRET":   mustB64("signup"),
		"KEK":             mustB64("kek"),
		"DB_SECRET":       mustB64("db"),
		"KEY_REF_SECRET":  mustB64("keyref"),
		"USERNAME_SECRET": mustB64("uname"),
	}
	km, err := InitStaticKeyManager(cfg)
	if err != nil {
		t.Fatalf("InitStaticKeyManager failed: %v", err)
	}
	if string(km.JWTKey()) != "jwt" {
		t.Errorf("JWTKey = %q, want 'jwt'", string(km.JWTKey()))
	}
	if string(km.SignupKey()) != "signup" {
		t.Errorf("SignupKey = %q, want 'signup'", string(km.SignupKey()))
	}
	if string(km.KEK()) != "kek" {
		t.Errorf("KEK = %q, want 'kek'", string(km.KEK()))
	}
	if string(km.DBKey()) != "db" {
		t.Errorf("DBKey = %q, want 'db'", string(km.DBKey()))
	}
	keyRef, err := km.HashKey("keyReference")
	if err != nil || string(keyRef) != "keyref" {
		t.Errorf("HashKey(keyReference) = %q, err=%v, want 'keyref'", string(keyRef), err)
	}
	uname, err := km.HashKey("username")
	if err != nil || string(uname) != "uname" {
		t.Errorf("HashKey(username) = %q, err=%v, want 'uname'", string(uname), err)
	}
}

func TestInitStaticKeyManager_BadBase64(t *testing.T) {
	cfg := c.KmsConfig{
		"JWT_SECRET":      "notbase64",
		"SIGNUP_SECRET":   mustB64("signup"),
		"KEK":             mustB64("kek"),
		"DB_SECRET":       mustB64("db"),
		"KEY_REF_SECRET":  mustB64("keyref"),
		"USERNAME_SECRET": mustB64("uname"),
	}
	_, err := InitStaticKeyManager(cfg)
	if err == nil {
		t.Error("expected error for bad base64 JWT_SECRET, got nil")
	}
}

func TestStaticKeyManager_HashKey_NotFound(t *testing.T) {
	cfg := c.KmsConfig{
		"JWT_SECRET":      mustB64("jwt"),
		"SIGNUP_SECRET":   mustB64("signup"),
		"KEK":             mustB64("kek"),
		"DB_SECRET":       mustB64("db"),
		"KEY_REF_SECRET":  mustB64("keyref"),
		"USERNAME_SECRET": mustB64("uname"),
	}
	km, err := InitStaticKeyManager(cfg)
	if err != nil {
		t.Fatalf("InitStaticKeyManager failed: %v", err)
	}
	_, err = km.HashKey("notfound")
	if err == nil {
		t.Error("expected error for missing hash key, got nil")
	}
}
