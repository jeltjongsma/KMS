package clients

import (
	c "kms/internal/bootstrap/context"
	kmsErrors "kms/pkg/errors"
	pHttp "kms/pkg/http"
	"net/http"
)

type Handler struct {
	Service ClientService
	Logger  c.Logger
}

func NewHandler(clientService ClientService, logger c.Logger) *Handler {
	return &Handler{
		Service: clientService,
		Logger:  logger,
	}
}

type ClientService interface {
	GetAll() ([]Client, *kmsErrors.AppError)
}

func (h *Handler) GetAllDev(w http.ResponseWriter, r *http.Request) *kmsErrors.AppError {
	clients, appErr := h.Service.GetAll()
	if appErr != nil {
		return appErr
	}
	return pHttp.WriteJSON(w, clients)
}
