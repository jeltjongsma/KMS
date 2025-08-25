package auth

import (
	"kms/internal/test/mocks"
	kmsErrors "kms/pkg/errors"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestHandler_Signup_Success(t *testing.T) {
	mockService := NewAuthServiceMock()
	mockService.SignupFunc = func(cred *SignupCredentials) (string, *kmsErrors.AppError) {
		return "jwt", nil
	}
	mockLogger := mocks.NewLoggerMock()
	handler := NewHandler(mockService, mockLogger)

	req := httptest.NewRequest("POST", "/auth/signup", strings.NewReader(`{"token": "signup", "password": "password"}`))
	rr := httptest.NewRecorder()

	err := handler.Signup(rr, req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.Contains(rr.Body.String(), `"token":"jwt"`) {
		t.Errorf("expected \"token\":\"jwt\", got: %v", rr.Body.String())
	}
}

func TestHandler_Signup_ParseBodyError(t *testing.T) {
	mockService := NewAuthServiceMock()
	mockLogger := mocks.NewLoggerMock()
	handler := NewHandler(mockService, mockLogger)

	req := httptest.NewRequest("POST", "/auth/signup", strings.NewReader(`{"token": "signup", "password": "password"`))
	rr := httptest.NewRecorder()

	err := handler.Signup(rr, req)
	if err == nil {
		t.Fatalf("expected error")
	}
	if !strings.Contains(err.Err.Error(), "unexpected EOF") {
		t.Errorf("expected error: unexpected EOF, got: %v", err.Err.Error())
	}
	if err.Code != 400 {
		t.Errorf("handler returned wrong status code: got %v want %v", err.Code, 400)
	}
}

func TestHandler_Signup_InvalidBodyError(t *testing.T) {
	mockService := NewAuthServiceMock()
	mockLogger := mocks.NewLoggerMock()
	handler := NewHandler(mockService, mockLogger)

	req := httptest.NewRequest("POST", "/auth/signup", strings.NewReader(`{"password": "password"}`))
	rr := httptest.NewRecorder()

	err := handler.Signup(rr, req)
	if err == nil {
		t.Fatalf("expected error")
	}
	if !strings.Contains(err.Err.Error(), "token and password should be non-empty") {
		t.Errorf("expected error: token and password should be non-empty, got: %v", err.Err.Error())
	}
	if err.Code != 400 {
		t.Errorf("handler returned wrong status code: got %v want %v", err.Code, 400)
	}
}

func TestHandler_Signup_ServiceError(t *testing.T) {
	mockService := NewAuthServiceMock()
	mockService.SignupFunc = func(cred *SignupCredentials) (string, *kmsErrors.AppError) {
		return "", kmsErrors.NewAppError(nil, "service error", 500)
	}
	mockLogger := mocks.NewLoggerMock()
	handler := NewHandler(mockService, mockLogger)

	req := httptest.NewRequest("POST", "/auth/signup", strings.NewReader(`{"token": "signup", "password": "password"}`))
	rr := httptest.NewRecorder()

	err := handler.Signup(rr, req)
	if err == nil {
		t.Fatalf("expected error")
	}
	if !strings.Contains(err.Message, "service error") {
		t.Errorf("expected service error, got: %v", err.Message)
	}
	if err.Code != 500 {
		t.Errorf("handler returned wrong status code: got %v want %v", err.Code, 500)
	}
}

func TestHandler_Login_Success(t *testing.T) {
	mockService := NewAuthServiceMock()
	mockService.LoginFunc = func(cred *Credentials) (string, *kmsErrors.AppError) {
		return "jwt", nil
	}
	mockLogger := mocks.NewLoggerMock()
	handler := NewHandler(mockService, mockLogger)

	req := httptest.NewRequest("POST", "/auth/login", strings.NewReader(`{"clientname": "client", "password": "password"}`))
	rr := httptest.NewRecorder()

	err := handler.Login(rr, req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.Contains(rr.Body.String(), `"token":"jwt"`) {
		t.Errorf("expected \"token\":\"jwt\", got: %v", rr.Body.String())
	}
}

func TestHandler_Login_ParseBodyError(t *testing.T) {
	mockService := NewAuthServiceMock()
	mockLogger := mocks.NewLoggerMock()
	handler := NewHandler(mockService, mockLogger)

	req := httptest.NewRequest("POST", "/auth/login", strings.NewReader(`{"clientname": "client", "password": "password"`))
	rr := httptest.NewRecorder()

	err := handler.Login(rr, req)
	if err == nil {
		t.Fatalf("expected error")
	}
	if !strings.Contains(err.Err.Error(), "unexpected EOF") {
		t.Errorf("expected error: unexpected EOF, got: %v", err.Err.Error())
	}
	if err.Code != 400 {
		t.Errorf("handler returned wrong status code: got %v want %v", err.Code, 400)
	}
}

func TestHandler_Login_InvalidBodyError(t *testing.T) {
	mockService := NewAuthServiceMock()
	mockLogger := mocks.NewLoggerMock()
	handler := NewHandler(mockService, mockLogger)

	req := httptest.NewRequest("POST", "/auth/login", strings.NewReader(`{"password": "password"}`))
	rr := httptest.NewRecorder()

	err := handler.Login(rr, req)
	if err == nil {
		t.Fatalf("expected error")
	}
	if !strings.Contains(err.Err.Error(), "clientname and password should be non-empty") {
		t.Errorf("expected error: clientname and password should be non-empty, got: %v", err.Err.Error())
	}
	if err.Code != 400 {
		t.Errorf("handler returned wrong status code: got %v want %v", err.Code, 400)
	}
}

func TestHandler_Login_ServiceError(t *testing.T) {
	mockService := NewAuthServiceMock()
	mockService.LoginFunc = func(cred *Credentials) (string, *kmsErrors.AppError) {
		return "", kmsErrors.NewAppError(nil, "service error", 500)
	}
	mockLogger := mocks.NewLoggerMock()
	handler := NewHandler(mockService, mockLogger)

	req := httptest.NewRequest("POST", "/auth/login", strings.NewReader(`{"clientname": "client", "password": "password"}`))
	rr := httptest.NewRecorder()

	err := handler.Login(rr, req)
	if err == nil {
		t.Fatalf("expected error")
	}
	if !strings.Contains(err.Message, "service error") {
		t.Errorf("expected service error, got: %v", err.Message)
	}
	if err.Code != 500 {
		t.Errorf("handler returned wrong status code: got %v want %v", err.Code, 500)
	}
}
