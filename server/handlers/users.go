package handlers

import (
	"net/http"
	"kms/utils"
	"kms/utils/kmsErrors"
	"kms/server/services"
)

type UserHandler struct {
	UserService 	*services.UserService
}

func NewUserHandler(userService *services.UserService) *UserHandler {
	return &UserHandler{UserService: userService}
}

func (h *UserHandler) GetAllDev(w http.ResponseWriter, r *http.Request) *kmsErrors.AppError {
	users, appErr := h.UserService.GetAll()
	if appErr != nil {
		return appErr
	}
	return utils.WriteJSON(w, users)
} 
