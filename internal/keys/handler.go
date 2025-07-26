package keys

import (
	c "kms/internal/bootstrap/context"
	"kms/internal/httpctx"
	kmsErrors "kms/pkg/errors"
	pHttp "kms/pkg/http"
	"kms/pkg/json"
	"net/http"
	"strconv"
)

type Handler struct {
	Service KeyService
	Logger  c.Logger
}

func NewHandler(keyService KeyService, logger c.Logger) *Handler {
	return &Handler{
		Service: keyService,
		Logger:  logger,
	}
}

type KeyService interface {
	CreateKey(userId int, keyReference string) (*Key, *kmsErrors.AppError)
	GetKey(id int, keyReference string) (*Key, *kmsErrors.AppError)
	GetAll() ([]Key, *kmsErrors.AppError)
}

func (h *Handler) GenerateKey(w http.ResponseWriter, r *http.Request) *kmsErrors.AppError {
	token, err := httpctx.ExtractToken(r.Context())
	if err != nil {
		return kmsErrors.NewInternalServerError(err)
	}

	userId, err := strconv.Atoi(token.Payload.Sub)
	if err != nil {
		return kmsErrors.NewInternalServerError(err)
	}

	var requestBody GenerateKeyRequest
	if err := json.ParseBody(r.Body, &requestBody); err != nil {
		return kmsErrors.NewAppError(err, "Invalid request body", 400)
	}

	key, appErr := h.Service.CreateKey(userId, requestBody.KeyReference)
	if appErr != nil {
		return appErr
	}

	response := &KeyReponse{
		DEK:      key.DEK,
		Encoding: key.Encoding,
	}

	return pHttp.WriteJSON(w, response)
}

func (h *Handler) GetKey(w http.ResponseWriter, r *http.Request) *kmsErrors.AppError {
	token, err := httpctx.ExtractToken(r.Context())
	if err != nil {
		return kmsErrors.NewInternalServerError(err)
	}

	userId, err := strconv.Atoi(token.Payload.Sub)
	if err != nil {
		return kmsErrors.NewInternalServerError(err)
	}

	keyReference, err := httpctx.GetRouteParam(r.Context(), "keyReference")
	if err != nil {
		return kmsErrors.NewInternalServerError(err)
	}

	key, appErr := h.Service.GetKey(userId, keyReference)
	if appErr != nil {
		return appErr
	}

	response := &KeyReponse{
		DEK:      key.DEK,
		Encoding: key.Encoding,
	}

	return pHttp.WriteJSON(w, response)
}

func (h *Handler) GetAllDev(w http.ResponseWriter, r *http.Request) *kmsErrors.AppError {
	keys, appErr := h.Service.GetAll()
	if appErr != nil {
		return appErr
	}
	return pHttp.WriteJSON(w, keys)
}
