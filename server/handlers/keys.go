package handlers

import (
	"net/http"
	"kms/storage"
	"kms/server/dto"
	"kms/utils"
	"kms/server/auth"
	"kms/server/services"
	"kms/utils/kmsErrors"
	"kms/server/router"
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

	var requestBody dto.GenerateKeyRequest
	if err := utils.ParseJSONBody(r.Body, &requestBody); err != nil {
		return kmsErrors.NewAppError(err, "Invalid request body", 400)
	}

	key, appErr := h.KeyService.CreateKey(token.Payload.Sub, requestBody.KeyReference)
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

	keyReference, err := router.GetRouteParam(r.Context(), "keyReference")
	if err != nil {
		return kmsErrors.NewInternalServerError(err)
	}

	key, appErr := h.KeyService.GetKey(token.Payload.Sub, keyReference)
	if appErr != nil {
		return appErr
	}

	response := &dto.KeyReponse{
		DEK: key.DEK,
		Encoding: key.Encoding,
	}

	return utils.WriteJSON(w, response)
}

// Dev only
func MakeKeyHandler(keyRepo storage.KeyRepository) http.HandlerFunc {
	return func (w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			keys, err := keyRepo.GetAll()
			if utils.HandleErrAndSendHttp(w, err, "Failed to retrieve keys", http.StatusInternalServerError) {return}

			utils.SendEncodedJSON(w, keys)
			return

		default:
			utils.ReturnMethodNotAllowed(w)
		}
	}
}
