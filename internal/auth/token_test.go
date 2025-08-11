package auth

import (
	b64 "encoding/base64"
	"kms/internal/clients"
	"strconv"
	"strings"
	"testing"
	"time"
)

func Test_Roundtrip_Success(t *testing.T) {
	secret := []byte("testsecret")
	genInfo := &TokenGenInfo{
		Ttl:    3600,
		Secret: secret,
		Typ:    "test",
	}
	client := &clients.Client{
		ID:         1,
		Clientname: "testclient",
	}

	tokenStr, err := GenerateJWT(genInfo, client)
	if err != nil {
		t.Fatalf("GenerateJWT failed: %v", err)
	}

	token, err := VerifyToken(tokenStr, secret)
	if err != nil {
		t.Fatalf("VerifyToken failed: %v", err)
	}
	if token.Payload.Sub != "1" || token.Payload.Ttl != 3600 {
		t.Errorf("unexpected token payload: %+v", token.Payload)
	}
	if token.Header.Typ != "test" || token.Header.Ver != "1" {
		t.Errorf("unexpected token header: %+v", token.Header)
	}
	if token.Payload.Iat <= 0 {
		t.Error("expected Iat to be a positive timestamp")
	}
}

func Test_GenerateToken_Valid(t *testing.T) {
	secret := []byte("validsecret")
	header := &TokenHeader{
		Ver: "1",
		Typ: "test",
	}
	payload := &TokenPayload{
		Sub: "testclient",
		Ttl: 3600,
		Iat: time.Now().UnixMilli(),
	}
	token := &Token{
		Header:  header,
		Payload: payload,
	}
	tokenStr, err := GenerateToken(token, secret)
	if err != nil {
		t.Fatalf("GenerateToken failed: %v", err)
	}
	parts := strings.Split(tokenStr, ".")
	if len(parts) != 3 {
		t.Fatalf("expected token to have 3 parts, got %d", len(parts))
	}
	decodedHeader, err := b64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		t.Fatalf("failed to decode header: %v", err)
	}
	decodedPayload, err := b64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatalf("failed to decode payload: %v", err)
	}
	if string(decodedHeader) != `{"ver":"1","typ":"test"}` {
		t.Errorf("expected header to match, got %s", string(decodedHeader))
	}
	if string(decodedPayload) != `{"sub":"testclient","ttl":3600,"iat":`+strconv.FormatInt(payload.Iat, 10)+`}` {
		t.Errorf("expected payload to match, got %s", string(decodedPayload))
	}
}

func Test_GenerateJWT_Valid(t *testing.T) {
	secret := []byte("jwtsecret")
	genInfo := &TokenGenInfo{
		Ttl:    3600,
		Secret: secret,
		Typ:    "jwt",
	}
	tokenStr, err := GenerateJWT(genInfo, &clients.Client{ID: 1, Clientname: "testclient"})
	if err != nil {
		t.Fatalf("GenerateJWT failed: %v", err)
	}
	parts := strings.Split(tokenStr, ".")
	if len(parts) != 3 {
		t.Fatalf("expected JWT to have 3 parts, got %d", len(parts))
	}
	decodedHeader, err := b64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		t.Fatalf("failed to decode JWT header: %v", err)
	}
	decodedPayload, err := b64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatalf("failed to decode JWT payload: %v", err)
	}
	if string(decodedHeader) != `{"ver":"1","typ":"jwt"}` {
		t.Errorf("expected JWT header to match, got %s", string(decodedHeader))
	}
	if !strings.Contains(string(decodedPayload), `"sub":"1"`) || !strings.Contains(string(decodedPayload), `"ttl":3600`) {
		t.Errorf("expected JWT payload to contain client ID and TTL, got %s", string(decodedPayload))
	}
}

func Test_GenerateSignupToken_Valid(t *testing.T) {
	secret := []byte("signupsecret")
	genInfo := &TokenGenInfo{
		Ttl:    3600,
		Secret: secret,
		Typ:    "signup",
	}
	tokenStr, err := GenerateSignupToken(genInfo, "testclient")
	if err != nil {
		t.Fatalf("GenerateSignupToken failed: %v", err)
	}
	parts := strings.Split(tokenStr, ".")
	if len(parts) != 3 {
		t.Fatalf("expected SignupToken to have 3 parts, got %d", len(parts))
	}
	decodedHeader, err := b64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		t.Fatalf("failed to decode SignupToken header: %v", err)
	}
	decodedPayload, err := b64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatalf("failed to decode SignupToken payload: %v", err)
	}
	if string(decodedHeader) != `{"ver":"1","typ":"signup"}` {
		t.Errorf("expected SignupToken header to match, got %s", string(decodedHeader))
	}
	if !strings.Contains(string(decodedPayload), `"sub":"testclient"`) || !strings.Contains(string(decodedPayload), `"ttl":3600`) {
		t.Errorf("expected SignupToken payload to contain clientname and TTL, got %s", string(decodedPayload))
	}
}

func Test_VerifyToken_InvalidInputs(t *testing.T) {
	secret := []byte("testsecret")
	wrongSecret := []byte("wrongsecret")
	validToken, err := GenerateJWT(&TokenGenInfo{
		Ttl:    3600,
		Secret: secret,
		Typ:    "test",
	}, &clients.Client{ID: 1, Clientname: "testclient"})
	if err != nil {
		t.Fatalf("GenerateJWT failed: %v", err)
	}
	expiredToken, err := GenerateToken(&Token{
		Header: &TokenHeader{Ver: "1", Typ: "test"},
		Payload: &TokenPayload{
			Sub: "1",
			Ttl: 1800,                          // Short TTL for testing
			Iat: time.Now().UnixMilli() - 3600, // IAT in the past
		}}, secret)
	if err != nil {
		t.Fatalf("GenerateToken failed for expired token: %v", err)
	}

	// Test cases for invalid inputs
	tests := []struct {
		name     string
		token    string
		secret   []byte
		expected string
	}{
		{
			name:     "Invalid signature",
			token:    validToken + "invalidsignature",
			secret:   secret,
			expected: "MACs don't match",
		},
		{
			name:     "Invalid token pattern",
			token:    "abc.xyz",
			secret:   secret,
			expected: "Not a JWT",
		},
		{
			name:     "TTL has passed",
			token:    expiredToken,
			secret:   secret,
			expected: "TTL has passed",
		},
		{
			name:     "Wrong secret",
			token:    validToken,
			secret:   wrongSecret,
			expected: "MACs don't match",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := VerifyToken(tt.token, tt.secret)
			if err == nil || !strings.Contains(err.Error(), tt.expected) {
				t.Errorf("VerifyToken(%q, %q) = %v, want error containing %q", tt.token, string(tt.secret), err, tt.expected)
			}
		})
	}
}
