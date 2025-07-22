package auth

import (
	"net/http"
	kmsErrors "kms/pkg/errors"
	pkgHttp "kms/pkg/http"
	"kms/internal/api/dto"
	"kms/pkg/json"
)

type Handler struct {
	Service 	*Service
}

func NewHandler(authService *Service) *Handler {
	return &Handler{
		Service: authService,
	}
}

// TODO: Minimum password requirements
func (h *Handler) Signup(w http.ResponseWriter, r *http.Request) *kmsErrors.AppError {
	var cred SignupCredentials 
	if err := json.ParseBody(r.Body, &cred); err != nil {
		return kmsErrors.NewInvalidBodyError(err)
	}

	if err := cred.Validate(); err != nil {
		return kmsErrors.NewMissingCredentialsError(err)
	}

	jwt, appErr := h.Service.Signup(&cred)
	if appErr != nil {
		return appErr
	}

	response := &dto.TokenResponse{
		Token: jwt,
	}

	return pkgHttp.WriteJSON(w, response)
}

func (h *Handler) Login(w http.ResponseWriter, r *http.Request) *kmsErrors.AppError {
	var cred Credentials
	if err := json.ParseBody(r.Body, &cred); err != nil {
		return kmsErrors.NewInvalidBodyError(err)
	}

	if err := cred.Validate(); err != nil {
		return kmsErrors.NewMissingCredentialsError(err)
	}

	jwt, appErr := h.Service.Login(&cred)
	if appErr != nil {
		return appErr
	}

	response := &dto.TokenResponse{
		Token: jwt,
	}

	return pkgHttp.WriteJSON(w, response)
}
