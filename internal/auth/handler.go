package auth

import (
	"kms/internal/api/dto"
	c "kms/internal/bootstrap/context"
	kmsErrors "kms/pkg/errors"
	pHttp "kms/pkg/http"
	"kms/pkg/json"
	"net/http"
)

type Handler struct {
	Service AuthService
	Logger  c.Logger
}

func NewHandler(authService AuthService, logger c.Logger) *Handler {
	return &Handler{
		Service: authService,
		Logger:  logger,
	}
}

type AuthService interface {
	Signup(*SignupCredentials) (string, *kmsErrors.AppError)
	Login(*Credentials) (string, *kmsErrors.AppError)
}

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

	return pHttp.WriteJSON(w, response)
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

	return pHttp.WriteJSON(w, response)
}
