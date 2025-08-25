package httpctx

import (
	"context"
	"encoding/json"
	"errors"
	"kms/internal/auth"
	"kms/internal/test/mocks"
	kmsErrors "kms/pkg/errors"
	pHttp "kms/pkg/http"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestGetRouteParam(t *testing.T) {
	ctx := context.WithValue(context.Background(), RouteParamsCtxKey, map[string]string{
		"clientID": "123",
	})

	tests := []struct {
		name     string
		paramKey string
		expected string
		wantErr  bool
		wantMsg  string
	}{
		{"ValidParam", "clientID", "123", false, ""},
		{"InvalidParam", "invalid", "", true, "param (invalid) not in path"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := GetRouteParam(ctx, tt.paramKey)
			if tt.wantErr {
				if err == nil {
					t.Errorf("GetRouteParam(%q) expected error, got nil", tt.paramKey)
				} else if !strings.Contains(err.Error(), tt.wantMsg) {
					t.Errorf("GetRouteParam(%q) error = %v, want %v", tt.paramKey, err.Error(), tt.wantMsg)
				}
			} else {
				if err != nil {
					t.Errorf("GetRouteParam(%q) unexpected error: %v", tt.paramKey, err)
				} else if got != tt.expected {
					t.Errorf("GetRouteParam(%q) = %q, want %q", tt.paramKey, got, tt.expected)
				}
			}
		})
	}
}

func TestGetRouteParam_MissingContext(t *testing.T) {
	ctx := context.Background() // No route params set

	_, err := GetRouteParam(ctx, "clientID")
	if err == nil {
		t.Error("GetRouteParam expected error, got nil")
	} else if !strings.Contains(err.Error(), "no route params in context") {
		t.Errorf("GetRouteParam error = %v, want 'no route params in context'", err)
	}
}

func TestExtractToken(t *testing.T) {
	ctx := context.WithValue(context.Background(), TokenCtxKey, auth.Token{
		Payload: &auth.TokenPayload{Sub: "123"},
	})

	token, err := ExtractToken(ctx)
	if err != nil {
		t.Errorf("ExtractToken failed: %v", err)
	}
	if token == nil || token.Payload.Sub != "123" {
		t.Errorf("Extracted token does not match expected value")
	}
}

func TestExtractToken_MissingContext(t *testing.T) {
	ctx := context.Background() // No token set

	_, err := ExtractToken(ctx)
	if err == nil {
		t.Error("ExtractToken expected error, got nil")
	} else if !strings.Contains(err.Error(), "no token in context") {
		t.Errorf("ExtractToken error = %v, want 'no token in context'", err)
	}
}

func TestNewAppHandler_Success(t *testing.T) {
	mockLogger := mocks.NewLoggerMock()
	handler := AppHandler(func(w http.ResponseWriter, r *http.Request) *kmsErrors.AppError {
		// Check if request ID is set in context
		reqID := r.Context().Value(RequestIDKey)
		if reqID == nil {
			return kmsErrors.NewInternalServerError(errors.New("missing request ID in context"))
		}
		w.WriteHeader(http.StatusOK)
		pHttp.WriteJSON(w, map[string]string{"message": "success"})
		return nil
	})
	appHandler := NewAppHandler(mockLogger, handler)
	req, err := http.NewRequest("GET", "/test", nil)
	if err != nil {
		t.Fatalf("Failed to create request: %v", err)
	}
	rr := httptest.NewRecorder()
	appHandler.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Errorf("Expected status code 200, got: %d", rr.Code)
	}
	var body map[string]string
	if err := json.Unmarshal(rr.Body.Bytes(), &body); err != nil {
		t.Errorf("Failed to parse response body: %v", err)
	}
	if body["message"] != "success" {
		t.Errorf("Expected response body to be '{\"message\":\"success\"}', got: %s", rr.Body.String())
	}
	requestId := rr.Header().Get("X-Request-ID")
	if requestId == "" {
		t.Error("Expected X-Request-ID header to be set, got empty")
	}
}

func TestNewAppHandler_Error(t *testing.T) {
	mockLogger := mocks.NewLoggerMock()

	tests := []struct {
		name       string
		errMsg     string
		statusCode int
	}{
		{"InternalServerError", "Internal server error", http.StatusInternalServerError},
		{"BadRequestError", "Bad request", http.StatusBadRequest},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			handler := AppHandler(func(w http.ResponseWriter, r *http.Request) *kmsErrors.AppError {
				return kmsErrors.NewAppError(errors.New(tt.errMsg), tt.errMsg, tt.statusCode)
			})
			appHandler := NewAppHandler(mockLogger, handler)
			req, err := http.NewRequest("GET", "/test", nil)
			if err != nil {
				t.Fatalf("Failed to create request: %v", err)
			}
			rr := httptest.NewRecorder()
			appHandler.ServeHTTP(rr, req)
			if rr.Code != tt.statusCode {
				t.Errorf("Expected status code %d, got: %d", tt.statusCode, rr.Code)
			}
			if !strings.Contains(rr.Body.String(), tt.errMsg) {
				t.Errorf("Expected response body to contain '%s', got: %s", tt.errMsg, rr.Body.String())
			}
		})
	}
}
