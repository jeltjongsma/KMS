package middleware

import (
	"context"
	"errors"
	"kms/internal/auth"
	"kms/internal/clients"
	"kms/internal/httpctx"
	kmsErrors "kms/pkg/errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestAuthorize_Success(t *testing.T) {
	// Mock JWT secret and token
	jwtSecret := []byte("testsecret")
	token, err := auth.GenerateJWT(&auth.TokenGenInfo{
		Ttl:    3600,
		Secret: jwtSecret,
		Typ:    "jwt",
	}, &clients.Client{
		ID:         1,
		Clientname: "testclient",
	})
	if err != nil {
		t.Fatalf("failed to generate token: %v", err)
	}

	// Mock the next handler
	next := func(w http.ResponseWriter, r *http.Request) *kmsErrors.AppError {
		// Check if the context contains the token
		ctxToken := r.Context().Value(httpctx.TokenCtxKey)
		if ctxToken == nil {
			return kmsErrors.NewAppError(
				nil,
				"Unauthorized",
				401,
			)
		}
		if ctxToken.(auth.Token).Header.Typ != "jwt" {
			return kmsErrors.NewAppError(
				nil,
				"Invalid token type",
				401,
			)
		}

		// If everything is fine, return OK
		w.WriteHeader(http.StatusOK)
		return nil
	}

	// Create a mock request with the Authorization header
	handler := Authorize(jwtSecret)(next)
	req, err := http.NewRequest("GET", "/test", nil)
	if err != nil {
		t.Fatalf("failed to create request: %v", err)
	}
	req.Header.Set("Authorization", "Bearer "+token)

	// Create a ResponseRecorder to capture the response
	rr := httptest.NewRecorder()

	// Call the handler
	appErr := handler(rr, req)
	if appErr != nil {
		t.Fatalf("handler returned an error: %v", appErr)
	}
	if rr.Code != http.StatusOK {
		t.Errorf("handler returned wrong status code: got %v want %v", rr.Code, http.StatusOK)
	}
}

// Missing token -> bearer token missing
// Invalid bearer -> invalid bearer token
func TestAuthorize_InvalidHeader(t *testing.T) {
	// Mock JWT secret
	jwtSecret := []byte("testsecret")
	// Mock the next handler
	next := func(w http.ResponseWriter, r *http.Request) *kmsErrors.AppError {
		return nil // This handler should not be called
	}
	wrongToken, err := auth.GenerateJWT(&auth.TokenGenInfo{
		Ttl:    3600,
		Secret: jwtSecret,
		Typ:    "other",
	}, &clients.Client{
		ID:         1,
		Clientname: "testclient",
	})
	if err != nil {
		t.Fatalf("failed to generate wrong token: %v", err)
	}
	// Create a handler with the Authorize middleware
	handler := Authorize(jwtSecret)(next)

	tests := []struct {
		name     string
		header   string
		expected string
	}{
		{
			name:     "Missing Authorization header",
			header:   "",
			expected: "bearer token missing",
		},
		{
			name:     "Invalid Authorization header format",
			header:   "InvalidHeader",
			expected: "invalid bearer token",
		},
		{
			name:     "Invalid Bearer token",
			header:   "Bearer invalidtoken",
			expected: "Not a JWT",
		},
		{
			name:     "Non-JWT token type",
			header:   "Bearer " + wrongToken,
			expected: "Token should be of type 'jwt'",
		},
		{
			name:     "Empty Bearer token",
			header:   "Bearer ",
			expected: "invalid bearer token",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create a mock request with the Authorization header
			req, err := http.NewRequest("GET", "/test", nil)
			if err != nil {
				t.Fatalf("failed to create request: %v", err)
			}
			if tt.header != "" {
				req.Header.Set("Authorization", tt.header)
			}

			// Create a ResponseRecorder to capture the response
			rr := httptest.NewRecorder()

			// Call the handler
			appErr := handler(rr, req)

			if appErr == nil {
				t.Fatal("expected an error, got nil")
			}
			if appErr.Code != 401 {
				t.Errorf("handler returned wrong status code: got %v want %v", appErr.Code, 401)
			}
			if appErr.Message != "Unauthorized" {
				t.Errorf("handler returned wrong message: got %v want %v", appErr.Message, "Unauthorized")
			}
			if !strings.Contains(appErr.Err.Error(), tt.expected) {
				t.Errorf("expected error to contain '%s', got: %v", tt.expected, appErr.Err)
			}
		})
	}
}

func TestRequireAdmin_Success(t *testing.T) {
	// Mock client repository
	clientRepo := clients.NewClientRepositoryMock()
	clientRepo.GetRoleFunc = func(clientID int) (string, error) {
		return "admin", nil // Mock admin role
	}

	// Mock the next handler
	next := func(w http.ResponseWriter, r *http.Request) *kmsErrors.AppError {
		w.WriteHeader(http.StatusOK)
		return nil
	}

	handler := RequireAdmin(clientRepo)(next)

	req, err := http.NewRequest("GET", "/admin", nil)
	if err != nil {
		t.Fatalf("failed to create request: %v", err)
	}

	ctx := context.WithValue(req.Context(), httpctx.TokenCtxKey, auth.Token{
		Payload: &auth.TokenPayload{
			Sub: "1", // Mock client ID
		},
	})

	rr := httptest.NewRecorder()
	appErr := handler(rr, req.WithContext(ctx))
	if appErr != nil {
		t.Fatalf("handler returned an error: %v", appErr)
	}
	if rr.Code != http.StatusOK {
		t.Errorf("handler returned wrong status code: got %v want %v", rr.Code, http.StatusOK)
	}
}

// Missing token -> Internal server error
// Invalid client ID -> Internal server error
// Repo error -> Internal server error
// Forbidden role -> Forbidden

func TestRequireAdmin_Error(t *testing.T) {
	clientRepoError := clients.NewClientRepositoryMock()
	clientRepoError.GetRoleFunc = func(clientID int) (string, error) {
		return "", errors.New("repo error") // Mock repository error
	}
	clientRepoForbidden := clients.NewClientRepositoryMock()
	clientRepoForbidden.GetRoleFunc = func(clientID int) (string, error) {
		return "client", nil // Mock non-admin role
	}

	tests := []struct {
		name       string
		clientRepo clients.ClientRepository
		token      auth.Token
		wantCode   int
	}{
		{
			name:       "Invalid client ID",
			clientRepo: clientRepoError, // Will not be called
			token: auth.Token{Payload: &auth.TokenPayload{
				Sub: "invalid", // Invalid client ID
			}},
			wantCode: 500,
		},
		{
			name:       "Repository error",
			clientRepo: clientRepoError,
			token: auth.Token{Payload: &auth.TokenPayload{
				Sub: "1", // Valid client ID
			}},
			wantCode: 500,
		},
		{
			name:       "Forbidden role",
			clientRepo: clientRepoForbidden,
			token: auth.Token{Payload: &auth.TokenPayload{
				Sub: "1", // Valid client ID
			}},
			wantCode: 403,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			handler := RequireAdmin(tt.clientRepo)(func(w http.ResponseWriter, r *http.Request) *kmsErrors.AppError {
				return nil // This handler should not be called
			})

			req, err := http.NewRequest("GET", "/admin", nil)
			if err != nil {
				t.Fatalf("failed to create request: %v", err)
			}

			ctx := context.WithValue(req.Context(), httpctx.TokenCtxKey, tt.token)
			rr := httptest.NewRecorder()

			appErr := handler(rr, req.WithContext(ctx))
			if appErr == nil {
				t.Fatal("expected an error, got nil")
			}
			if appErr.Code != tt.wantCode {
				t.Errorf("handler returned wrong status code: got %v want %v", appErr.Code, tt.wantCode)
			}
		})
	}
}

func TestRequireAdmin_MissingToken(t *testing.T) {
	// Mock client repository
	clientRepo := clients.NewClientRepositoryMock()
	clientRepo.GetRoleFunc = func(clientID int) (string, error) {
		return "admin", nil // Mock admin role
	}

	// Mock the next handler
	next := func(w http.ResponseWriter, r *http.Request) *kmsErrors.AppError {
		return nil // This handler should not be called
	}

	handler := RequireAdmin(clientRepo)(next)

	req, err := http.NewRequest("GET", "/admin", nil)
	if err != nil {
		t.Fatalf("failed to create request: %v", err)
	}

	rr := httptest.NewRecorder()
	appErr := handler(rr, req)
	if appErr == nil {
		t.Fatal("expected an error, got nil")
	}
	if appErr.Code != 500 {
		t.Errorf("handler returned wrong status code: got %v want %v", appErr.Code, 500)
	}
	if appErr.Message != "Internal server error" {
		t.Errorf("handler returned wrong message: got %v want %v", appErr.Message, "Internal server error")
	}
}
