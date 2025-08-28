package sdk

import (
	"io"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"
)

func TestNewClient(t *testing.T) {
	// Backup original env vars
	origBase := os.Getenv("KMS_BASE_URL")
	origUser := os.Getenv("KMS_USER")
	origPass := os.Getenv("KMS_PASS")
	origSkipVerify := os.Getenv("KMS_INSECURE_SKIP_VERIFY")
	defer func() {
		os.Setenv("KMS_BASE_URL", origBase)
		os.Setenv("KMS_USER", origUser)
		os.Setenv("KMS_PASS", origPass)
		os.Setenv("KMS_INSECURE_SKIP_VERIFY", origSkipVerify)
	}()

	// Clear env vars for testing missing config
	os.Unsetenv("KMS_BASE_URL")
	os.Unsetenv("KMS_USER")
	os.Unsetenv("KMS_PASS")
	os.Unsetenv("KMS_INSECURE_SKIP_VERIFY")

	_, err := NewClient()
	if err != ErrMissingConfig {
		t.Fatalf("expected ErrMissingConfig, got %v", err)
	}

	// Set env vars for testing valid config
	os.Setenv("KMS_BASE_URL", "https://example.com")
	os.Setenv("KMS_USER", "testuser")
	os.Setenv("KMS_PASS", "testpass")
	os.Setenv("KMS_INSECURE_SKIP_VERIFY", "true")

	c, err := NewClient()
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if c.base != "https://example.com" {
		t.Errorf("expected base URL to be https://example.com, got %s", c.base)
	}
	if c.user != "testuser" {
		t.Errorf("expected user to be testuser, got %s", c.user)
	}
	if c.pass != "testpass" {
		t.Errorf("expected pass to be testpass, got %s", c.pass)
	}
	if c.http == nil {
		t.Error("expected http client to be initialized")
	}
	if c.http.Transport == nil {
		t.Error("expected http transport to be initialized")
	} else {
		tr, ok := c.http.Transport.(*http.Transport)
		if !ok {
			t.Errorf("expected transport to be *http.Transport, got %T", c.http.Transport)
		} else if tr.TLSClientConfig == nil || !tr.TLSClientConfig.InsecureSkipVerify {
			t.Error("expected TLSClientConfig with InsecureSkipVerify=true")
		}
	}
}

func TestTokenOrLogin(t *testing.T) {
	rt := roundTripFunc(func(req *http.Request) *http.Response {
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

	err := c.tokenOrLogin()
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if c.token != "fake-token" {
		t.Errorf("expected token to be fake-token, got %s", c.token)
	}
	if time.Now().After(c.expiresAt) {
		t.Error("expected expiresAt to be in the future")
	}

	// Call again to test cached token path
	err = c.tokenOrLogin()
	if err != nil {
		t.Fatalf("expected no error on cached token, got %v", err)
	}
}

func TestTokenOrLogin_Fail(t *testing.T) {
	rt := roundTripFunc(func(req *http.Request) *http.Response {
		if req.URL.Path == "/auth/login" {
			return &http.Response{
				StatusCode: 401,
				Body:       io.NopCloser(strings.NewReader("Unauthorized")),
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

	err := c.tokenOrLogin()
	if err == nil {
		t.Fatalf("expected error, got none")
	}
}

func TestForceRefresh(t *testing.T) {
	callCount := 0
	rt := roundTripFunc(func(req *http.Request) *http.Response {
		if req.URL.Path == "/auth/login" {
			callCount++
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

	err := c.tokenOrLogin()
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if callCount != 1 {
		t.Errorf("expected 1 call to login, got %d", callCount)
	}

	err = c.forceRefresh()
	if err != nil {
		t.Fatalf("expected no error on force refresh, got %v", err)
	}
	if callCount != 2 {
		t.Errorf("expected 2 calls to login after force refresh, got %d", callCount)
	}
}
