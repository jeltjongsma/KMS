package users

import (
	c "kms/internal/bootstrap/context"
	kmsErrors "kms/pkg/errors"
	pHttp "kms/pkg/http"
	"net/http"
)

type Handler struct {
	Service UserService
	Logger  c.Logger
}

func NewHandler(userService UserService, logger c.Logger) *Handler {
	return &Handler{
		Service: userService,
		Logger:  logger,
	}
}

type UserService interface {
	GetAll() ([]User, *kmsErrors.AppError)
}

func (h *Handler) GetAllDev(w http.ResponseWriter, r *http.Request) *kmsErrors.AppError {
	users, appErr := h.Service.GetAll()
	if appErr != nil {
		return appErr
	}
	return pHttp.WriteJSON(w, users)
}
