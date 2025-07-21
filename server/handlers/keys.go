package handlers

import (
	"net/http"
	"kms/server/dto"
	"kms/utils"
	"kms/server/auth"
	"kms/server/services"
	"kms/utils/kmsErrors"
	"kms/server/router"
	"strconv"
)

type KeyHandler struct {
	KeyService 	*services.KeyService
}

func NewKeyHandler(keyService *services.KeyService) *KeyHandler {
	return &KeyHandler{
		KeyService: keyService,
	}
}

func (h *KeyHandler) GenerateKey(w http.ResponseWriter, r *http.Request) *kmsErrors.AppError {
	token, err := auth.ExtractToken(r.Context())
	if err != nil {
		return kmsErrors.NewInternalServerError(err)
	}

	userId, err := strconv.Atoi(token.Payload.Sub)
	if err != nil {
		return kmsErrors.NewInternalServerError(err)
	}

	var requestBody dto.GenerateKeyRequest
	if err := utils.ParseJSONBody(r.Body, &requestBody); err != nil {
		return kmsErrors.NewAppError(err, "Invalid request body", 400)
	}

	key, appErr := h.KeyService.CreateKey(userId, requestBody.KeyReference)
	if appErr != nil {
		return appErr
	}

	response := &dto.KeyReponse{
		DEK: key.DEK,
		Encoding: key.Encoding,
	}

	return utils.WriteJSON(w, response)
}

func (h *KeyHandler) GetKey(w http.ResponseWriter, r *http.Request) *kmsErrors.AppError {
	token, err := auth.ExtractToken(r.Context())
	if err != nil {
		return kmsErrors.NewInternalServerError(err)
	}

	userId, err := strconv.Atoi(token.Payload.Sub)
	if err != nil {
		return kmsErrors.NewInternalServerError(err)
	}

	keyReference, err := router.GetRouteParam(r.Context(), "keyReference")
	if err != nil {
		return kmsErrors.NewInternalServerError(err)
	}

	key, appErr := h.KeyService.GetKey(userId, keyReference)
	if appErr != nil {
		return appErr
	}

	response := &dto.KeyReponse{
		DEK: key.DEK,
		Encoding: key.Encoding,
	}

	return utils.WriteJSON(w, response)
}

func (h *KeyHandler) GetAllDev(w http.ResponseWriter, r *http.Request) *kmsErrors.AppError {
	keys, appErr := h.KeyService.GetAll()
	if appErr != nil {
		return appErr
	}
	return utils.WriteJSON(w, keys)
}
