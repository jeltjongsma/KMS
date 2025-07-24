package auth

import (
	"net/http"
	kmsErrors "kms/pkg/errors"
	pHttp "kms/pkg/http"
	"kms/internal/api/dto"
	"kms/pkg/json"
	c "kms/internal/bootstrap/context"
)

type Handler struct {
	Service 	*Service
	Logger 		c.Logger
}

func NewHandler(authService *Service, logger c.Logger) *Handler {
	return &Handler{
		Service: authService,
		Logger: logger,
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
