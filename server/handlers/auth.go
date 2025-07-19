package handlers

import (
	"kms/utils"
	"kms/server/dto"
	"net/http"
	"kms/utils/kmsErrors"
	"kms/server/services"
)

type AuthHandler struct {
	AuthService 	*services.AuthService
}

func NewAuthHandler(authService *services.AuthService) *AuthHandler {
	return &AuthHandler{
		AuthService: authService,
	}
}

// TODO: Minimum password requirements
func (h *AuthHandler) Signup(w http.ResponseWriter, r *http.Request) *kmsErrors.AppError {
	var cred dto.Credentials 
	if err := utils.ParseJSONBody(r.Body, &cred); err != nil {
		return kmsErrors.NewAppError(err, "Invalid request body", 400)
	}

	if err := cred.Validate(); err != nil {
		return kmsErrors.NewAppError(err, "Missing credentials", 400)
	}

	jwt, appErr := h.AuthService.Signup(&cred)
	if appErr != nil {
		return appErr
	}

	response := &dto.JWTResponse{
		JWT: jwt,
	}

	return utils.WriteJSON(w, response)
}

func (h *AuthHandler) Login(w http.ResponseWriter, r *http.Request) *kmsErrors.AppError {
	var cred dto.Credentials
	if err := utils.ParseJSONBody(r.Body, &cred); err != nil {
		return kmsErrors.NewAppError(err, "Invalid request body", 400)
	}

	if err := cred.Validate(); err != nil {
		return kmsErrors.NewAppError(err, "Missing credentials", 400)
	}

	jwt, appErr := h.AuthService.Login(&cred)
	if appErr != nil {
		return appErr
	}

	response := &dto.JWTResponse{
		JWT: jwt,
	}

	return utils.WriteJSON(w, response)
}
