package keys

import (
	"net/http"
	"strconv"
	kmsErrors "kms/pkg/errors"
	pkgHttp "kms/pkg/http"
	"kms/pkg/json"
	"kms/internal/httpctx"
)

type Handler struct {
	Service 	*Service
}

func NewHandler(keyService *Service) *Handler {
	return &Handler{
		Service: keyService,
	}
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
		DEK: key.DEK,
		Encoding: key.Encoding,
	}

	return pkgHttp.WriteJSON(w, response)
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
		DEK: key.DEK,
		Encoding: key.Encoding,
	}

	return pkgHttp.WriteJSON(w, response)
}

func (h *Handler) GetAllDev(w http.ResponseWriter, r *http.Request) *kmsErrors.AppError {
	keys, appErr := h.Service.GetAll()
	if appErr != nil {
		return appErr
	}
	return pkgHttp.WriteJSON(w, keys)
}
