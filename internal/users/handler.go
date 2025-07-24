package users

import (
	"net/http"
	kmsErrors "kms/pkg/errors"
	pHttp "kms/pkg/http"
	c "kms/internal/bootstrap/context"
)

type Handler struct {
	Service 	*Service
	Logger 		c.Logger
}

func NewHandler(userService *Service, logger c.Logger) *Handler {
	return &Handler{
		Service: userService,
		Logger: logger,
	}
}

func (h *Handler) GetAllDev(w http.ResponseWriter, r *http.Request) *kmsErrors.AppError {
	users, appErr := h.Service.GetAll()
	if appErr != nil {
		return appErr
	}
	return pHttp.WriteJSON(w, users)
} 
