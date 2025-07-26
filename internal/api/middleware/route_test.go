package middleware

import (
	kmsErrors "kms/pkg/errors"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestMakeRouter_Success(t *testing.T) {
	handler := func(w http.ResponseWriter, r *http.Request) *kmsErrors.AppError {
		w.WriteHeader(http.StatusOK)
		return nil
	}
	routes := []*Route{
		NewRoute("GET", "/test", handler),
	}
	router := MakeRouter(routes)
	req, err := http.NewRequest("GET", "/test", nil)
	if err != nil {
		t.Fatalf("failed to create request: %v", err)
	}
	rr := httptest.NewRecorder()
	respErr := router(rr, req)
	if respErr != nil {
		t.Fatalf("expected no error, got: %v", respErr)
	}
	if rr.Code != http.StatusOK {
		t.Errorf("expected status code 200, got: %d", rr.Code)
	}
}

func TestMakeRouter_NotFound(t *testing.T) {
	handler := func(w http.ResponseWriter, r *http.Request) *kmsErrors.AppError {
		w.WriteHeader(http.StatusOK)
		return nil
	}
	routes := []*Route{
		NewRoute("GET", "/test", handler),
	}
	router := MakeRouter(routes)
	req, err := http.NewRequest("GET", "/notfound", nil)
	if err != nil {
		t.Fatalf("failed to create request: %v", err)
	}
	rr := httptest.NewRecorder()
	respErr := router(rr, req)
	if respErr == nil {
		t.Fatal("expected an error, got nil")
	}
	if respErr.Code != http.StatusNotFound {
		t.Errorf("expected status code 404, got: %d", respErr.Code)
	}
}

func TestMatchPattern_Simple(t *testing.T) {
	route := NewRoute("GET", "/test/{id}", func(w http.ResponseWriter, r *http.Request) *kmsErrors.AppError {
		return nil
	})

	tests := []struct {
		path     string
		expected bool
	}{
		{"/test/123", true},
		{"/test/abc", true},
		{"/test/", false},
		{"/other/123", false},
		{"/test/123/extra", false},
		{"/test/{id}", true}, // Router doesn't care about the actual value of {id}
	}

	for _, tt := range tests {
		req, err := http.NewRequest("GET", tt.path, nil)
		if err != nil {
			t.Fatalf("failed to create request: %v", err)
		}
		params, ok := matchPattern(route, req)
		if ok != tt.expected {
			t.Errorf("expected matchPattern(%s) to return %v, got %v", tt.path, tt.expected, ok)
			continue
		}
		if ok && params["id"] == "" {
			t.Errorf("expected 'id' parameter to be set for path %s", tt.path)
		}
	}
}

func TestMatchPattern_MultipleParams(t *testing.T) {
	route := NewRoute("GET", "/test/{id}/{name}", func(w http.ResponseWriter, r *http.Request) *kmsErrors.AppError {
		return nil
	})
	tests := []struct {
		path     string
		expected bool
	}{
		{"/test/123/john", true},
		{"/test/456/jane", true},
		{"/test/123", false},
		{"/test/john/123", true}, // Router doesn't care about param types
		{"/test/123/john/extra", false},
		{"/test/{id}/{name}", true}, // Router doesn't care about the actual values of {id} and {name}
	}
	for _, tt := range tests {
		req, err := http.NewRequest("GET", tt.path, nil)
		if err != nil {
			t.Fatalf("failed to create request: %v", err)
		}
		params, ok := matchPattern(route, req)
		if ok != tt.expected {
			t.Errorf("expected matchPattern(%s) to return %v, got %v", tt.path, tt.expected, ok)
			continue
		}
		if ok && (params["id"] == "" || params["name"] == "") {
			t.Error("expected 'id' and 'name' parameters to be set for path", tt.path)
		}
	}
}
