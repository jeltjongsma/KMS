package keys

import (
	"context"
	"kms/internal/auth"
	"kms/internal/httpctx"
	"kms/internal/test"
	"kms/internal/test/mocks"
	kmsErrors "kms/pkg/errors"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestHandler_GenerateKey_Success(t *testing.T) {
	mockService := NewKeyServiceMock()
	mockService.CreateKeyFunc = func(clientId int, keyReference string) (*Key, *kmsErrors.AppError) {
		return &Key{
			DEK:      "dek",
			Encoding: "encoding",
		}, nil
	}
	mockLogger := mocks.NewLoggerMock()
	handler := NewHandler(mockService, mockLogger)

	req := httptest.NewRequest("POST", "/keys/actions/generate", strings.NewReader(`{"keyReference": "keyRef"}`))
	ctx := context.WithValue(req.Context(), httpctx.TokenCtxKey, auth.Token{
		Payload: &auth.TokenPayload{
			Sub: "1",
		},
	})
	req = req.WithContext(ctx)
	rr := httptest.NewRecorder()

	err := handler.GenerateKey(rr, req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.Contains(rr.Body.String(), `"dek":"dek","version":0,"encoding":"encoding"`) {
		t.Errorf("expected \"dek\":\"dek\",\"version\":0,\"encoding\":\"encoding\", got: %v", rr.Body.String())
	}
}

func TestHandler_GenerateKey_MissingToken(t *testing.T) {
	mockService := NewKeyServiceMock()
	mockLogger := mocks.NewLoggerMock()
	handler := NewHandler(mockService, mockLogger)

	req := httptest.NewRequest("POST", "/keys/actions/generate", strings.NewReader(`{"keyReference": "keyRef"}`))
	rr := httptest.NewRecorder()

	err := handler.GenerateKey(rr, req)
	if err == nil {
		t.Fatalf("expected error")
	}
	if !strings.Contains(err.Err.Error(), "no token in context") {
		t.Errorf("expected error: no token in context, got: %v", err.Err.Error())
	}
	if err.Code != 500 {
		t.Errorf("handler returned wrong status code: got %v want %v", err.Code, 500)
	}
}

func TestHandler_GenerateKey_InvalidClientIdError(t *testing.T) {
	mockService := NewKeyServiceMock()
	mockLogger := mocks.NewLoggerMock()
	handler := NewHandler(mockService, mockLogger)

	req := httptest.NewRequest("POST", "/keys/actions/generate", strings.NewReader(`{"keyReference": "keyRef"}`))
	ctx := context.WithValue(req.Context(), httpctx.TokenCtxKey, auth.Token{
		Payload: &auth.TokenPayload{
			Sub: "clientId",
		},
	})
	req = req.WithContext(ctx)
	rr := httptest.NewRecorder()

	err := handler.GenerateKey(rr, req)
	if err == nil {
		t.Fatalf("expected error")
	}
	if !strings.Contains(err.Err.Error(), "strconv.Atoi: parsing") {
		t.Errorf("expected error: strconv.Atoi: parsing, got: %v", err.Err.Error())
	}
	if err.Code != 500 {
		t.Errorf("handler returned wrong status code: got %v want %v", err.Code, 500)
	}
}

func TestHandler_GenerateKey_ParseBodyError(t *testing.T) {
	mockService := NewKeyServiceMock()
	mockLogger := mocks.NewLoggerMock()
	handler := NewHandler(mockService, mockLogger)

	req := httptest.NewRequest("POST", "/keys/actions/generate", strings.NewReader(`{"keyReference": "keyRef"`))
	ctx := context.WithValue(req.Context(), httpctx.TokenCtxKey, auth.Token{
		Payload: &auth.TokenPayload{
			Sub: "1",
		},
	})
	req = req.WithContext(ctx)
	rr := httptest.NewRecorder()

	err := handler.GenerateKey(rr, req)
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

func TestHandler_GenerateKey_ServiceError(t *testing.T) {
	mockService := NewKeyServiceMock()
	mockService.CreateKeyFunc = func(clientId int, keyReference string) (*Key, *kmsErrors.AppError) {
		return nil, kmsErrors.NewAppError(nil, "service error", 500)
	}
	mockLogger := mocks.NewLoggerMock()
	handler := NewHandler(mockService, mockLogger)

	req := httptest.NewRequest("POST", "/keys/actions/generate", strings.NewReader(`{"keyReference": "keyRef"}`))
	ctx := context.WithValue(req.Context(), httpctx.TokenCtxKey, auth.Token{
		Payload: &auth.TokenPayload{
			Sub: "1",
		},
	})
	req = req.WithContext(ctx)
	rr := httptest.NewRecorder()

	err := handler.GenerateKey(rr, req)
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

func TestHandler_GetKey_Success(t *testing.T) {
	mockService := NewKeyServiceMock()
	mockService.GetKeyFunc = func(clientId int, keyReference string, version int) (*Key, *kmsErrors.AppError) {
		return &Key{
			DEK:      "dek",
			Version:  1,
			Encoding: "encoding",
		}, nil
	}
	mockLogger := mocks.NewLoggerMock()
	handler := NewHandler(mockService, mockLogger)

	req := httptest.NewRequest("POST", "/keys/keyRef", nil)
	ctx := context.WithValue(req.Context(), httpctx.TokenCtxKey, auth.Token{
		Payload: &auth.TokenPayload{
			Sub: "1",
		},
	})
	ctx_ := context.WithValue(ctx, httpctx.RouteParamsCtxKey, map[string]string{
		"keyReference": "keyRef",
		"version":      "1",
	})
	req = req.WithContext(ctx_)
	rr := httptest.NewRecorder()

	err := handler.GetKey(rr, req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.Contains(rr.Body.String(), `"dek":"dek","version":1,"encoding":"encoding"`) {
		t.Errorf("expected \"dek\":\"dek\",\"version\":1,\"encoding\":\"encoding\", got: %v", rr.Body.String())
	}
}

func TestHandler_GetKey_MissingToken(t *testing.T) {
	mockService := NewKeyServiceMock()
	mockLogger := mocks.NewLoggerMock()
	handler := NewHandler(mockService, mockLogger)

	req := httptest.NewRequest("POST", "/keys/keyRef", nil)
	rr := httptest.NewRecorder()

	err := handler.GetKey(rr, req)
	if err == nil {
		t.Fatalf("expected error")
	}
	if !strings.Contains(err.Err.Error(), "no token in context") {
		t.Errorf("expected error: no token in context, got: %v", err.Err.Error())
	}
	if err.Code != 500 {
		t.Errorf("handler returned wrong status code: got %v want %v", err.Code, 500)
	}
}

func TestHandler_GetKey_InvalidClientIdError(t *testing.T) {
	mockService := NewKeyServiceMock()
	mockLogger := mocks.NewLoggerMock()
	handler := NewHandler(mockService, mockLogger)

	req := httptest.NewRequest("POST", "/keys/keyRef", nil)
	ctx := context.WithValue(req.Context(), httpctx.TokenCtxKey, auth.Token{
		Payload: &auth.TokenPayload{
			Sub: "clientId",
		},
	})
	req = req.WithContext(ctx)
	rr := httptest.NewRecorder()

	err := handler.GetKey(rr, req)
	if err == nil {
		t.Fatalf("expected error")
	}
	if !strings.Contains(err.Err.Error(), "strconv.Atoi: parsing") {
		t.Errorf("expected error: strconv.Atoi: parsing, got: %v", err.Err.Error())
	}
	if err.Code != 500 {
		t.Errorf("handler returned wrong status code: got %v want %v", err.Code, 500)
	}
}

func TestHandler_GetKey_MissingRouteParam(t *testing.T) {
	mockService := NewKeyServiceMock()
	mockLogger := mocks.NewLoggerMock()
	handler := NewHandler(mockService, mockLogger)

	req := httptest.NewRequest("POST", "/keys/keyRef", nil)
	ctx := context.WithValue(req.Context(), httpctx.TokenCtxKey, auth.Token{
		Payload: &auth.TokenPayload{
			Sub: "1",
		},
	})
	req = req.WithContext(ctx)
	rr := httptest.NewRecorder()

	err := handler.GetKey(rr, req)
	if err == nil {
		t.Fatalf("expected error")
	}
	if !strings.Contains(err.Err.Error(), "no route params in context") {
		t.Errorf("expected error: no route params in context, got: %v", err.Err.Error())
	}
	if err.Code != 500 {
		t.Errorf("handler returned wrong status code: got %v want %v", err.Code, 500)
	}
}

func TestHandler_GetKey_ServiceError(t *testing.T) {
	mockService := NewKeyServiceMock()
	mockService.GetKeyFunc = func(clientId int, keyReference string, version int) (*Key, *kmsErrors.AppError) {
		return nil, kmsErrors.NewAppError(nil, "service error", 500)
	}
	mockLogger := mocks.NewLoggerMock()
	handler := NewHandler(mockService, mockLogger)

	req := httptest.NewRequest("POST", "/keys/keyRef", nil)
	ctx := context.WithValue(req.Context(), httpctx.TokenCtxKey, auth.Token{
		Payload: &auth.TokenPayload{
			Sub: "1",
		},
	})
	ctx_ := context.WithValue(ctx, httpctx.RouteParamsCtxKey, map[string]string{
		"keyReference": "keyRef",
		"version":      "1",
	})
	req = req.WithContext(ctx_)
	rr := httptest.NewRecorder()

	err := handler.GetKey(rr, req)
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

func TestHandler_RenewKey_Success(t *testing.T) {
	mockService := NewKeyServiceMock()
	mockService.RenewKeyFunc = func(clientId int, keyReference string) (*Key, *kmsErrors.AppError) {
		return &Key{
			DEK:      "dek",
			Encoding: "encoding",
		}, nil
	}
	mockLogger := mocks.NewLoggerMock()
	handler := NewHandler(mockService, mockLogger)

	req := httptest.NewRequest("PATCH", "/keys/keyRef/renew", nil)
	ctx := context.WithValue(req.Context(), httpctx.TokenCtxKey, auth.Token{
		Payload: &auth.TokenPayload{
			Sub: "1",
		},
	})
	ctx_ := context.WithValue(ctx, httpctx.RouteParamsCtxKey, map[string]string{
		"keyReference": "keyRef",
	})
	req = req.WithContext(ctx_)
	rr := httptest.NewRecorder()

	err := handler.RenewKey(rr, req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if rr.Code != 200 {
		t.Errorf("expected status 200, got %d", rr.Code)
	}
	if !strings.Contains(rr.Body.String(), `{"dek":"dek","version":0,"encoding":"encoding"}`) {
		t.Errorf("unexpected body: %v", rr.Body.String())
	}
}

func TestHandler_RenewKey_MissingToken(t *testing.T) {
	mockService := NewKeyServiceMock()
	mockLogger := mocks.NewLoggerMock()
	handler := NewHandler(mockService, mockLogger)

	req := httptest.NewRequest("PATCH", "/keys/keyRef/renew", nil)
	ctx := context.WithValue(req.Context(), httpctx.TokenCtxKey, auth.Token{
		Payload: &auth.TokenPayload{
			Sub: "1",
		},
	})
	req = req.WithContext(ctx)
	rr := httptest.NewRecorder()

	err := handler.RenewKey(rr, req)
	if err == nil {
		t.Fatal("expected error")
	}

	if err.Code != 500 {
		t.Errorf("expected status 500, got %d", err.Code)
	}

	if !strings.Contains(err.Err.Error(), "no route params in context") {
		t.Errorf("expected no route params in context, got %v", err.Err)
	}
}

func TestHandler_RenewKey_MissingRouteParam(t *testing.T) {
	mockService := NewKeyServiceMock()
	mockLogger := mocks.NewLoggerMock()
	handler := NewHandler(mockService, mockLogger)

	req := httptest.NewRequest("PATCH", "/keys/keyRef/renew", nil)
	rr := httptest.NewRecorder()

	err := handler.RenewKey(rr, req)
	if err == nil {
		t.Fatal("expected error")
	}

	if err.Code != 500 {
		t.Errorf("expected status 500, got %d", err.Code)
	}

	if !strings.Contains(err.Err.Error(), "no token in context") {
		t.Errorf("expected no token in context, got %v", err.Err)
	}
}

func TestService_RenewKey_ServiceError(t *testing.T) {
	mockService := NewKeyServiceMock()
	mockService.RenewKeyFunc = func(clientId int, keyReference string) (*Key, *kmsErrors.AppError) {
		return nil, kmsErrors.NewAppError(nil, "service error", 500)
	}
	mockLogger := mocks.NewLoggerMock()
	handler := NewHandler(mockService, mockLogger)

	req := httptest.NewRequest("PATCH", "/keys/keyRef/renew", nil)
	ctx := context.WithValue(req.Context(), httpctx.TokenCtxKey, auth.Token{
		Payload: &auth.TokenPayload{
			Sub: "1",
		},
	})
	ctx_ := context.WithValue(ctx, httpctx.RouteParamsCtxKey, map[string]string{
		"keyReference": "keyRef",
	})
	req = req.WithContext(ctx_)
	rr := httptest.NewRecorder()

	err := handler.RenewKey(rr, req)
	if err == nil {
		t.Fatal("expected error")
	}

	if err.Code != 500 {
		t.Errorf("expected status 500, got %d", err.Code)
	}

	if !strings.Contains(err.Message, "service error") {
		t.Errorf("expected service error, got %v", err.Message)
	}
}

func TestHandler_DeleteKey_Success(t *testing.T) {
	mockService := NewKeyServiceMock()
	mockService.DeleteKeyFunc = func(clientId int, keyReference string) *kmsErrors.AppError {
		return nil
	}
	mockLogger := mocks.NewLoggerMock()
	handler := NewHandler(mockService, mockLogger)

	req := httptest.NewRequest("DELETE", "/keys/keyRef/actions/delete", nil)
	ctx := context.WithValue(req.Context(), httpctx.TokenCtxKey, auth.Token{
		Payload: &auth.TokenPayload{
			Sub: "1",
		},
	})
	ctx_ := context.WithValue(ctx, httpctx.RouteParamsCtxKey, map[string]string{
		"keyReference": "keyRef",
	})
	req = req.WithContext(ctx_)
	rr := httptest.NewRecorder()

	err := handler.DeleteKey(rr, req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if rr.Result().StatusCode != 204 {
		t.Errorf("expected status 204, got %d", rr.Result().StatusCode)
	}
}

func TestHandler_DeleteKey_MissingToken(t *testing.T) {
	mockService := NewKeyServiceMock()
	mockLogger := mocks.NewLoggerMock()
	handler := NewHandler(mockService, mockLogger)

	req := httptest.NewRequest("DELETE", "/keys/keyRef/actions/delete", nil)
	rr := httptest.NewRecorder()

	err := handler.DeleteKey(rr, req)
	if err == nil {
		t.Fatal("expected error")
	}

	if err.Code != 500 {
		t.Errorf("expected status 500, got %d", err.Code)
	}

	test.RequireContains(t, err.Err.Error(), "no token in context")
}

func TestHandler_DeleteKey_InvalidToken(t *testing.T) {
	mockService := NewKeyServiceMock()
	mockLogger := mocks.NewLoggerMock()
	handler := NewHandler(mockService, mockLogger)

	req := httptest.NewRequest("DELETE", "/keys/keyRef/actions/delete", nil)
	ctx := context.WithValue(req.Context(), httpctx.TokenCtxKey, auth.Token{
		Payload: &auth.TokenPayload{
			Sub: "sub",
		},
	})
	req = req.WithContext(ctx)
	rr := httptest.NewRecorder()

	err := handler.DeleteKey(rr, req)
	if err == nil {
		t.Fatal("expected error")
	}

	if err.Code != 500 {
		t.Errorf("expected status 500, got %d", err.Code)
	}

	test.RequireContains(t, err.Err.Error(), "strconv.Atoi: parsing")
}

func TestHandler_DeleteKey_MissingRouteParam(t *testing.T) {
	mockService := NewKeyServiceMock()
	mockLogger := mocks.NewLoggerMock()
	handler := NewHandler(mockService, mockLogger)

	req := httptest.NewRequest("DELETE", "/keys/keyRef/actions/delete", nil)
	ctx := context.WithValue(req.Context(), httpctx.TokenCtxKey, auth.Token{
		Payload: &auth.TokenPayload{
			Sub: "1",
		},
	})
	req = req.WithContext(ctx)
	rr := httptest.NewRecorder()

	err := handler.DeleteKey(rr, req)
	if err == nil {
		t.Fatal("expected error")
	}

	if err.Code != 500 {
		t.Errorf("expected status 500, got %d", err.Code)
	}

	test.RequireContains(t, err.Err.Error(), "no route params in context")
}

func TestHandler_DeleteKey_ServiceError(t *testing.T) {
	mockService := NewKeyServiceMock()
	mockService.DeleteKeyFunc = func(clientId int, keyReference string) *kmsErrors.AppError {
		return kmsErrors.NewAppError(nil, "service error", 500)
	}
	mockLogger := mocks.NewLoggerMock()
	handler := NewHandler(mockService, mockLogger)

	req := httptest.NewRequest("DELETE", "/keys/keyRef/actions/delete", nil)
	ctx := context.WithValue(req.Context(), httpctx.TokenCtxKey, auth.Token{
		Payload: &auth.TokenPayload{
			Sub: "1",
		},
	})
	ctx_ := context.WithValue(ctx, httpctx.RouteParamsCtxKey, map[string]string{
		"keyReference": "keyRef",
	})
	req = req.WithContext(ctx_)
	rr := httptest.NewRecorder()

	err := handler.DeleteKey(rr, req)
	if err == nil {
		t.Fatal("expected error")
	}

	if err.Code != 500 {
		t.Errorf("expected status 500, got %d", err.Code)
	}

	test.RequireContains(t, err.Message, "service error")
}

func TestHandler_GetAllDev_Success(t *testing.T) {
	mockService := NewKeyServiceMock()
	mockService.GetAllFunc = func() ([]Key, *kmsErrors.AppError) {
		return []Key{{
			KeyReference: "keyRef",
			DEK:          "dek",
		}}, nil
	}
	mockLogger := mocks.NewLoggerMock()
	handler := NewHandler(mockService, mockLogger)

	req := httptest.NewRequest("GET", "/keys", nil)
	rr := httptest.NewRecorder()

	err := handler.GetAllDev(rr, req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.Contains(rr.Body.String(), `{"id":0,"clientId":0,"keyReference":"keyRef","version":0,"dek":"dek","state":"","encoding":""}`) {
		t.Errorf("unexpected body: %v", rr.Body.String())
	}
}

func TestHandler_GetAllDev_ServiceError(t *testing.T) {
	mockService := NewKeyServiceMock()
	mockService.GetAllFunc = func() ([]Key, *kmsErrors.AppError) {
		return nil, kmsErrors.NewAppError(nil, "service error", 500)
	}
	mockLogger := mocks.NewLoggerMock()
	handler := NewHandler(mockService, mockLogger)

	req := httptest.NewRequest("GET", "/keys", nil)
	rr := httptest.NewRecorder()

	err := handler.GetAllDev(rr, req)
	if err == nil {
		t.Fatalf("expected error")
	}
	if !strings.Contains(err.Message, "service error") {
		t.Errorf("expected service error, got: %v", err.Message)
	}
}
