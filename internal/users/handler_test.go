package users

import (
	"kms/internal/test/mocks"
	kmsErrors "kms/pkg/errors"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestHandler_GetAllDev_Success(t *testing.T) {
	mockService := NewUserServiceMock()
	mockService.GetAllFunc = func() ([]User, *kmsErrors.AppError) {
		return []User{{
			ID:       1,
			Username: "user",
		}}, nil
	}
	mockLogger := mocks.NewLoggerMock()
	handler := NewHandler(mockService, mockLogger)

	req := httptest.NewRequest("GET", "/users", nil)
	rr := httptest.NewRecorder()

	err := handler.GetAllDev(rr, req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.Contains(rr.Body.String(), `{"id":1,"username":"user","hashedUsername":"","password":"","role":""}`) {
		t.Errorf("unexpected body: %v", rr.Body.String())
	}
}

func TestHandler_GetAllDev_ServiceError(t *testing.T) {
	mockService := NewUserServiceMock()
	mockService.GetAllFunc = func() ([]User, *kmsErrors.AppError) {
		return nil, kmsErrors.NewAppError(nil, "service error", 500)
	}
	mockLogger := mocks.NewLoggerMock()
	handler := NewHandler(mockService, mockLogger)

	req := httptest.NewRequest("GET", "/users", nil)
	rr := httptest.NewRecorder()

	err := handler.GetAllDev(rr, req)
	if err == nil {
		t.Fatalf("expected error")
	}
	if !strings.Contains(err.Message, "service error") {
		t.Errorf("expected service error, got: %v", err.Message)
	}
}
