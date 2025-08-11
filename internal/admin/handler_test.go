package admin

import (
	"context"
	"kms/internal/auth"
	"kms/internal/httpctx"
	"kms/internal/test"
	"kms/internal/test/mocks"
	"kms/internal/users"
	kmsErrors "kms/pkg/errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestHandler_UpdateRole_Success(t *testing.T) {
	mockService := NewAdminServiceMock()
	mockService.UpdateRoleFunc = func(userId int, role string, adminId string) *kmsErrors.AppError {
		return nil // Simulate successful role update
	}
	mockLogger := mocks.NewLoggerMock()
	handler := NewHandler(mockService, mockLogger)

	// Create a test request with a valid user ID and role
	req := httptest.NewRequest("POST", "/users/1/role", strings.NewReader(`{"role": "admin"}`))

	ctx := context.WithValue(req.Context(), httpctx.TokenCtxKey, auth.Token{
		Payload: &auth.TokenPayload{Sub: "admin-id"},
	})
	ctx_ := context.WithValue(ctx, httpctx.RouteParamsCtxKey, map[string]string{"id": "1"})

	req = req.WithContext(ctx_)

	rr := httptest.NewRecorder()

	// Call the handler
	appErr := handler.UpdateRole(rr, req)
	if appErr != nil {
		t.Fatalf("handler returned an error: %v", appErr)
	}
	if rr.Code != http.StatusNoContent {
		t.Errorf("handler returned wrong status code: got %v want %v", rr.Code, http.StatusNoContent)
	}
}

func TestHandler_UpdateRole_MissingTokenError(t *testing.T) {
	mockService := NewAdminServiceMock()
	mockLogger := mocks.NewLoggerMock()
	handler := NewHandler(mockService, mockLogger)

	// Create a test request with missing token
	req := httptest.NewRequest("POST", "/users/1/role", strings.NewReader((`{"role": "admin"}`)))

	rr := httptest.NewRecorder()

	appErr := handler.UpdateRole(rr, req)
	if appErr == nil {
		t.Errorf("expected error: no token in context")
		return
	}
	if !strings.Contains(appErr.Err.Error(), "no token in context") {
		t.Errorf("expected error: no token in context, but got: %v", appErr.Err.Error())
	}
	if appErr.Code != 500 {
		t.Errorf("handler returned wrong status code: got %v want %v", appErr.Code, 500)
	}
}

func TestHandler_UpdateRole_MissingParamError(t *testing.T) {
	mockService := NewAdminServiceMock()
	mockLogger := mocks.NewLoggerMock()
	handler := NewHandler(mockService, mockLogger)
	// Create a test request with missing param
	req := httptest.NewRequest("POST", "/users/1/role", strings.NewReader((`{"role": "admin"}`)))

	ctx := context.WithValue(req.Context(), httpctx.TokenCtxKey, auth.Token{
		Payload: &auth.TokenPayload{Sub: "admin-id"},
	})

	req = req.WithContext(ctx)

	rr := httptest.NewRecorder()

	appErr := handler.UpdateRole(rr, req)
	if appErr == nil {
		t.Errorf("expected error: no route params in context")
		return
	}
	if !strings.Contains(appErr.Err.Error(), "no route params in context") {
		t.Errorf("expected error: no route params in context, but got: %v", appErr.Err.Error())
	}
	if appErr.Code != 500 {
		t.Errorf("handler returned wrong status code: got %v want %v", appErr.Code, 500)
	}
}

func TestHandler_UpdateRole_NonIntIdError(t *testing.T) {
	mockService := NewAdminServiceMock()
	mockLogger := mocks.NewLoggerMock()
	handler := NewHandler(mockService, mockLogger)

	req := httptest.NewRequest("POST", "/users/userId/role", strings.NewReader((`{"role": "admin"}`)))

	ctx := context.WithValue(req.Context(), httpctx.TokenCtxKey, auth.Token{
		Payload: &auth.TokenPayload{Sub: "admin-id"},
	})

	// Set id param to string
	ctx_ := context.WithValue(ctx, httpctx.RouteParamsCtxKey, map[string]string{"id": "userId"})

	req = req.WithContext(ctx_)

	rr := httptest.NewRecorder()

	err := handler.UpdateRole(rr, req)
	if err == nil {
		t.Errorf("expected error: strconv.Atoi: parsing")
		return
	}
	if !strings.Contains(err.Err.Error(), "strconv.Atoi: parsing") {
		t.Errorf("expected error: strconv.Atoi: parsing, got: %v", err.Err.Error())
	}
	if err.Code != 400 {
		t.Errorf("handler returned wrong status code: got %v want %v", err.Code, 400)
	}
}

func TestHandler_UpdateRole_ParseBodyError(t *testing.T) {
	mockService := NewAdminServiceMock()
	mockLogger := mocks.NewLoggerMock()
	handler := NewHandler(mockService, mockLogger)

	req := httptest.NewRequest("POST", "/users/1/role", strings.NewReader((`{"role"}`)))

	ctx := context.WithValue(req.Context(), httpctx.TokenCtxKey, auth.Token{
		Payload: &auth.TokenPayload{Sub: "admin-id"},
	})

	ctx_ := context.WithValue(ctx, httpctx.RouteParamsCtxKey, map[string]string{"id": "1"})

	req = req.WithContext(ctx_)

	rr := httptest.NewRecorder()

	err := handler.UpdateRole(rr, req)
	if err == nil {
		t.Errorf("expected error: invalid character '}' after object key")
		return
	}
	if !strings.Contains(err.Err.Error(), "invalid character '}' after object key") {
		t.Errorf("expected error: invalid character '}' after object key, got: %v", err.Err.Error())
	}
	if err.Code != 400 {
		t.Errorf("handler returned wrong status code: got %v want %v", err.Code, 400)
	}
}

func TestHandler_UpdateRole_ServiceError(t *testing.T) {
	mockService := NewAdminServiceMock()
	mockService.UpdateRoleFunc = func(userId int, role string, adminId string) *kmsErrors.AppError {
		return kmsErrors.NewAppError(nil, "service error", 500)
	}
	mockLogger := mocks.NewLoggerMock()
	handler := NewHandler(mockService, mockLogger)

	req := httptest.NewRequest("POST", "/users/1/role", strings.NewReader((`{"role": "admin"}`)))

	ctx := context.WithValue(req.Context(), httpctx.TokenCtxKey, auth.Token{
		Payload: &auth.TokenPayload{Sub: "admin-id"},
	})

	ctx_ := context.WithValue(ctx, httpctx.RouteParamsCtxKey, map[string]string{"id": "1"})

	req = req.WithContext(ctx_)

	rr := httptest.NewRecorder()

	err := handler.UpdateRole(rr, req)
	if err == nil {
		t.Fatalf("expected service error")
	}
	if !strings.Contains(err.Message, "service error") {
		t.Errorf("expected service error, got: %v", err.Message)
	}
	if err.Code != 500 {
		t.Errorf("handler returned wrong status code: got %v want %v", err.Code, 500)
	}
}

func TestHandler_GenerateSignupToken_Success(t *testing.T) {
	mockService := NewAdminServiceMock()
	mockService.GenerateSignupTokenFunc = func(body *GenerateSignupTokenRequest, adminId string) (string, *kmsErrors.AppError) {
		return "jwt", nil
	}
	mockLogger := mocks.NewLoggerMock()
	handler := NewHandler(mockService, mockLogger)

	req := httptest.NewRequest("POST", "/auth/signup/generate", strings.NewReader((`{"username": "iot-device", "ttl": 3600}`)))

	ctx := context.WithValue(req.Context(), httpctx.TokenCtxKey, auth.Token{
		Payload: &auth.TokenPayload{Sub: "admin-id"},
	})

	req = req.WithContext(ctx)

	rr := httptest.NewRecorder()

	err := handler.GenerateSignupToken(rr, req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.Contains(rr.Body.String(), `"token":"jwt"`) {
		t.Errorf("unexpected body: %s, expected: \"token\":\"jwt\"", rr.Body.String())
	}
}

func TestHandler_GenerateSignupToken_MissingTokenError(t *testing.T) {
	mockService := NewAdminServiceMock()
	mockLogger := mocks.NewLoggerMock()
	handler := NewHandler(mockService, mockLogger)

	req := httptest.NewRequest("POST", "/auth/signup/generate", strings.NewReader((`{"username": "iot-device", "ttl": 3600}`)))

	rr := httptest.NewRecorder()

	err := handler.GenerateSignupToken(rr, req)
	if err == nil {
		t.Fatalf("expected error: no token in context")
	}
	if !strings.Contains(err.Err.Error(), "no token in context") {
		t.Errorf("expected error: no token in context, got: %v", err.Err.Error())
	}
	if err.Code != 500 {
		t.Errorf("handler returned wrong status code: got %v want %v", err.Code, 500)
	}
}

func TestHandler_GenerateSignupToken_ParseBodyError(t *testing.T) {
	mockService := NewAdminServiceMock()
	mockLogger := mocks.NewLoggerMock()
	handler := NewHandler(mockService, mockLogger)

	req := httptest.NewRequest("POST", "/auth/signup/generate", strings.NewReader((`{"username", "ttl": 3600}`)))

	ctx := context.WithValue(req.Context(), httpctx.TokenCtxKey, auth.Token{
		Payload: &auth.TokenPayload{Sub: "admin-id"},
	})

	req = req.WithContext(ctx)

	rr := httptest.NewRecorder()

	err := handler.GenerateSignupToken(rr, req)
	if err == nil {
		t.Fatalf("expected error: invalid character")
	}
	if !strings.Contains(err.Err.Error(), "invalid character") {
		t.Errorf("expected error: invalid character, got: %v", err.Err.Error())
	}
	if err.Code != 400 {
		t.Errorf("handler returned wrong status code: got %v want %v", err.Code, 400)
	}
}

func TestHandler_GenerateSignupToken_InvalidBodyError(t *testing.T) {
	mockService := NewAdminServiceMock()
	mockLogger := mocks.NewLoggerMock()
	handler := NewHandler(mockService, mockLogger)

	req := httptest.NewRequest("POST", "/auth/signup/generate", strings.NewReader((`{"ttl": 3600}`)))

	ctx := context.WithValue(req.Context(), httpctx.TokenCtxKey, auth.Token{
		Payload: &auth.TokenPayload{Sub: "admin-id"},
	})

	req = req.WithContext(ctx)

	rr := httptest.NewRecorder()

	err := handler.GenerateSignupToken(rr, req)
	if err == nil {
		t.Fatalf("expected error: username and ttl should be non-empty")
	}
	if !strings.Contains(err.Err.Error(), "username and ttl should be non-empty") {
		t.Errorf("expected error: username and ttl should be non-empty, got: %v", err.Err.Error())
	}
	if err.Code != 400 {
		t.Errorf("handler returned wrong status code: got %v want %v", err.Code, 400)
	}
}

func TestHandler_GenerateSignupToken_ServiceError(t *testing.T) {
	mockService := NewAdminServiceMock()
	mockService.GenerateSignupTokenFunc = func(body *GenerateSignupTokenRequest, adminId string) (string, *kmsErrors.AppError) {
		return "", kmsErrors.NewAppError(nil, "service error", 500)
	}
	mockLogger := mocks.NewLoggerMock()
	handler := NewHandler(mockService, mockLogger)

	req := httptest.NewRequest("POST", "/auth/signup/generate", strings.NewReader((`{"username": "iot-device", "ttl": 3600}`)))

	ctx := context.WithValue(req.Context(), httpctx.TokenCtxKey, auth.Token{
		Payload: &auth.TokenPayload{Sub: "admin-id"},
	})

	req = req.WithContext(ctx)

	rr := httptest.NewRecorder()

	err := handler.GenerateSignupToken(rr, req)
	if err == nil {
		t.Fatalf("expected service error")
	}
	if !strings.Contains(err.Message, "service error") {
		t.Errorf("expected service error, got: %v", err.Err.Error())
	}
	if err.Code != 500 {
		t.Errorf("handler returned wrong status code: got %v want %v", err.Code, 500)
	}
}

func TestHandler_GetUsers_Success(t *testing.T) {
	u := []users.User{
		{
			ID:       1,
			Username: "username",
		},
	}
	mockService := NewAdminServiceMock()
	mockService.GetUsersFunc = func() ([]users.User, *kmsErrors.AppError) {
		return u, nil
	}
	mockLogger := mocks.NewLoggerMock()
	handler := NewHandler(mockService, mockLogger)

	req := httptest.NewRequest("GET", "/users", nil)
	rr := httptest.NewRecorder()

	if err := handler.GetUsers(rr, req); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	test.RequireContains(t, rr.Body.String(), `"id":1,"username":"username"`)
}

func TestHandler_GetUsers_ServiceError(t *testing.T) {
	mockService := NewAdminServiceMock()
	mockService.GetUsersFunc = func() ([]users.User, *kmsErrors.AppError) {
		return nil, kmsErrors.NewAppError(nil, "service error", 500)
	}
	mockLogger := mocks.NewLoggerMock()
	handler := NewHandler(mockService, mockLogger)

	req := httptest.NewRequest("GET", "/users", nil)
	rr := httptest.NewRecorder()

	err := handler.GetUsers(rr, req)

	if err == nil {
		t.Fatal("expected service error")
	}

	test.RequireContains(t, err.Message, "service error")
}

func TestHandler_DeleteUser_Success(t *testing.T) {
	mockService := NewAdminServiceMock()
	mockService.DeleteUserFunc = func(userId int) *kmsErrors.AppError {
		return nil
	}
	mockLogger := mocks.NewLoggerMock()
	handler := NewHandler(mockService, mockLogger)

	req := httptest.NewRequest("DELETE", "/users/2", nil)
	ctx := context.WithValue(req.Context(), httpctx.RouteParamsCtxKey, map[string]string{"id": "2"})

	req = req.WithContext(ctx)

	rr := httptest.NewRecorder()

	err := handler.DeleteUser(rr, req)

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if rr.Result().StatusCode != 204 {
		t.Errorf("expected status 204, got %d", rr.Result().StatusCode)
	}
}

func TestHandler_DeleteUser_MissingRouteParam(t *testing.T) {
	mockService := NewAdminServiceMock()
	mockLogger := mocks.NewLoggerMock()
	handler := NewHandler(mockService, mockLogger)

	req := httptest.NewRequest("DELETE", "/users/2", nil)
	rr := httptest.NewRecorder()

	err := handler.DeleteUser(rr, req)

	if err == nil {
		t.Fatal("expected error, got nil")
	}

	test.RequireContains(t, err.Err.Error(), "no route params in context")
	if err.Code != 500 {
		t.Errorf("expected status 500, got %d", rr.Result().StatusCode)
	}
}

func TestHandler_DeleteUser_NonIntParam(t *testing.T) {
	mockService := NewAdminServiceMock()
	mockService.DeleteUserFunc = func(userId int) *kmsErrors.AppError {
		return nil
	}
	mockLogger := mocks.NewLoggerMock()
	handler := NewHandler(mockService, mockLogger)

	req := httptest.NewRequest("DELETE", "/users/2", nil)
	ctx := context.WithValue(req.Context(), httpctx.RouteParamsCtxKey, map[string]string{"id": "id"})

	req = req.WithContext(ctx)

	rr := httptest.NewRecorder()

	err := handler.DeleteUser(rr, req)
	if err == nil {
		t.Fatal("expected error, got nil")
	}

	test.RequireContains(t, err.Err.Error(), "strconv.Atoi: parsing")
	test.RequireContains(t, err.Message, "ID must be integer")
	if err.Code != 400 {
		t.Errorf("expected status 400, got %d", rr.Result().StatusCode)
	}
}

func TestHandler_DeleteUser_ServiceError(t *testing.T) {
	mockService := NewAdminServiceMock()
	mockService.DeleteUserFunc = func(userId int) *kmsErrors.AppError {
		return kmsErrors.NewAppError(nil, "service error", 500)
	}
	mockLogger := mocks.NewLoggerMock()
	handler := NewHandler(mockService, mockLogger)

	req := httptest.NewRequest("DELETE", "/users/2", nil)
	ctx := context.WithValue(req.Context(), httpctx.RouteParamsCtxKey, map[string]string{"id": "2"})

	req = req.WithContext(ctx)

	rr := httptest.NewRecorder()

	err := handler.DeleteUser(rr, req)
	if err == nil {
		t.Fatal("expected error, got nil")
	}

	test.RequireContains(t, err.Message, "service error")
}
