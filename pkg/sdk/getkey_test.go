package sdk

import (
	"io"
	"net/http"
	"strings"
	"testing"
)

func TestGetKey(t *testing.T) {
	fakeKeyResp := `{
	  "decryptWith": {
	    "dek": "MO4ak42AGQzQCzNXgLFWmWEiskcM_pXE8SGA5VDYmrY",
	    "version": 1,
	    "encoding": "base64url (RFC 4648)",
	    "expiresAt": "2025-08-27T14:35:48.3099733+02:00"
	  },
	  "encryptWith": {
	    "dek": "yM2v9WVI5rcMf5AuUUbFMnNsujnruEhLr8tfsmtskVw",
	    "version": 2,
	    "encoding": "base64url (RFC 4648)",
	    "expiresAt": "2025-08-27T14:35:48.3099733+02:00"
	  }
	}`
	fakeLoginResp := `{"token":"fake-token","ttl":3600}`
	rt := roundTripFunc(func(req *http.Request) *http.Response {
		if req.URL.Path == "/keys/example-key/1" {
			return &http.Response{
				StatusCode: 200,
				Body:       io.NopCloser(strings.NewReader(fakeKeyResp)),
				Header:     make(http.Header),
			}
		}
		if req.URL.Path == "/auth/login" {
			return &http.Response{
				StatusCode: 200,
				Body:       io.NopCloser(strings.NewReader(fakeLoginResp)),
				Header:     make(http.Header),
			}
		}
		t.Fatalf("unexpected path: %s", req.URL.Path)
		return nil
	})

	client := &http.Client{Transport: rt}
	c := &Client{
		base: "http://fake",
		user: "test",
		pass: "pass",
		http: client,
	}

	bundle, err := c.GetKey("example-key", 1)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	if bundle.EncryptWith.Version != 2 {
		t.Errorf("expected encryptWith version 2, got %d", bundle.EncryptWith.Version)
	}
	if bundle.DecryptWith.Version != 1 {
		t.Errorf("expected decryptWith version 1, got %d", bundle.DecryptWith.Version)
	}
	if bundle.EncryptWith.DEK != "yM2v9WVI5rcMf5AuUUbFMnNsujnruEhLr8tfsmtskVw" {
		t.Errorf("unexpected encryptWith DEK: %s", bundle.EncryptWith.DEK)
	}
	if bundle.DecryptWith.DEK != "MO4ak42AGQzQCzNXgLFWmWEiskcM_pXE8SGA5VDYmrY" {
		t.Errorf("unexpected decryptWith DEK: %s", bundle.DecryptWith.DEK)
	}
}

func TestGetKey_Refresh(t *testing.T) {
	fakeKeyResp := `{
	  "decryptWith": {
	    "dek": "MO4ak42AGQzQCzNXgLFWmWEiskcM_pXE8SGA5VDYmrY",
	    "version": 1,
	    "encoding": "base64url (RFC 4648)",
	    "expiresAt": "2025-08-27T14:35:48.3099733+02:00"
	  },
	  "encryptWith": {
	    "dek": "yM2v9WVI5rcMf5AuUUbFMnNsujnruEhLr8tfsmtskVw",
	    "version": 2,
	    "encoding": "base64url (RFC 4648)",
	    "expiresAt": "2025-08-27T14:35:48.3099733+02:00"
	  }
	}`
	fakeLoginResp := `{"token":"fake-token","ttl":3600}`
	var firstCall = true
	rt := roundTripFunc(func(req *http.Request) *http.Response {
		if req.URL.Path == "/keys/example-key/1" {
			if firstCall {
				firstCall = false
				return &http.Response{
					StatusCode: 401,
					Body:       io.NopCloser(strings.NewReader("Unauthorized")),
					Header:     make(http.Header),
				}
			}
			return &http.Response{
				StatusCode: 200,
				Body:       io.NopCloser(strings.NewReader(fakeKeyResp)),
				Header:     make(http.Header),
			}
		}
		if req.URL.Path == "/auth/login" {
			return &http.Response{
				StatusCode: 200,
				Body:       io.NopCloser(strings.NewReader(fakeLoginResp)),
				Header:     make(http.Header),
			}
		}
		t.Fatalf("unexpected path: %s", req.URL.Path)
		return nil
	})

	client := &http.Client{Transport: rt}
	c := &Client{
		base: "http://fake",
		user: "test",
		pass: "pass",
		http: client,
	}

	bundle, err := c.GetKey("example-key", 1)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	if bundle.EncryptWith.Version != 2 {
		t.Errorf("expected encryptWith version 2, got %d", bundle.EncryptWith.Version)
	}
	if bundle.DecryptWith.Version != 1 {
		t.Errorf("expected decryptWith version 1, got %d", bundle.DecryptWith.Version)
	}
	if bundle.EncryptWith.DEK != "yM2v9WVI5rcMf5AuUUbFMnNsujnruEhLr8tfsmtskVw" {
		t.Errorf("unexpected encryptWith DEK: %s", bundle.EncryptWith.DEK)
	}
	if bundle.DecryptWith.DEK != "MO4ak42AGQzQCzNXgLFWmWEiskcM_pXE8SGA5VDYmrY" {
		t.Errorf("unexpected decryptWith DEK: %s", bundle.DecryptWith.DEK)
	}
}

func TestGetKey_RefreshOnce(t *testing.T) {
	var callCount = 0
	rt := roundTripFunc(func(req *http.Request) *http.Response {
		if req.URL.Path == "/keys/example-key/1" {
			callCount++
			return &http.Response{
				StatusCode: 401,
				Body:       io.NopCloser(strings.NewReader("Unauthorized")),
				Header:     make(http.Header),
			}
		}
		if req.URL.Path == "/auth/login" {
			return &http.Response{
				StatusCode: 200,
				Body:       io.NopCloser(strings.NewReader(`{"token":"fake-token","ttl":3600}`)),
				Header:     make(http.Header),
			}
		}
		t.Fatalf("unexpected path: %s", req.URL.Path)
		return nil
	})

	client := &http.Client{Transport: rt}
	c := &Client{
		base: "http://fake",
		user: "test",
		pass: "pass",
		http: client,
	}

	_, err := c.GetKey("example-key", 1)
	if err == nil {
		t.Fatalf("expected error, got none")
	}

	if callCount != 2 {
		t.Errorf("expected 2 calls to key endpoint, got %d", callCount)
	}
}

func TestGetKey_Fail(t *testing.T) {
	rt := roundTripFunc(func(req *http.Request) *http.Response {
		if req.URL.Path == "/keys/example-key/1" {
			return &http.Response{
				StatusCode: 500,
				Body:       io.NopCloser(strings.NewReader("Internal Server Error")),
				Header:     make(http.Header),
			}
		}
		if req.URL.Path == "/auth/login" {
			return &http.Response{
				StatusCode: 200,
				Body:       io.NopCloser(strings.NewReader(`{"token":"fake-token","ttl":3600}`)),
				Header:     make(http.Header),
			}
		}
		t.Fatalf("unexpected path: %s", req.URL.Path)
		return nil
	})

	client := &http.Client{Transport: rt}
	c := &Client{
		base: "http://fake",
		user: "test",
		pass: "pass",
		http: client,
	}

	_, err := c.GetKey("example-key", 1)
	if err == nil {
		t.Fatalf("expected error, got none")
	}
}
