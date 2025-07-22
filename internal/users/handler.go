package users

import (
	"net/http"
	kmsErrors "kms/pkg/errors"
	pkgHttp "kms/pkg/http"
)

type Handler struct {
	Service 	*Service
}

func NewHandler(userService *Service) *Handler {
	return &Handler{Service: userService}
}

func (h *Handler) GetAllDev(w http.ResponseWriter, r *http.Request) *kmsErrors.AppError {
	users, appErr := h.Service.GetAll()
	if appErr != nil {
		return appErr
	}
	return pkgHttp.WriteJSON(w, users)
} 
