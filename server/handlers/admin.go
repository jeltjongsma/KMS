package handlers

import (
	"net/http"
	"kms/server/router"
	"kms/server/dto"
	"kms/server/services"
	"kms/server/auth"
	"kms/utils"
	"kms/utils/kmsErrors"
	"strconv"
)

type AdminHandler struct {
	AdminService 	*services.AdminService
}

func NewAdminHandler(adminService *services.AdminService) *AdminHandler {
	return &AdminHandler{
		AdminService: adminService,
	}
}

func (h *AdminHandler) UpdateRole(w http.ResponseWriter, r *http.Request) *kmsErrors.AppError {
	userIdStr, err := router.GetRouteParam(r.Context(), "id")
	if err != nil {
		return kmsErrors.NewAppError(err, "Missing route param", 500)
	}

	userId, err := strconv.Atoi(userIdStr)
	if err != nil {
		return kmsErrors.NewAppError(err, "ID must be integer", 400)
	}

	var requestBody dto.UpdateRoleRequest
	if err := utils.ParseJSONBody(r.Body, &requestBody); err != nil {
		return kmsErrors.NewAppError(err, "Invalid request body", 400)
	}

	if appErr := h.AdminService.UpdateRole(userId, requestBody.Role); err != nil {
		return appErr
	}

	utils.WriteStatus(w, 204)
	return nil
}

func (h *AdminHandler) Me(w http.ResponseWriter, r *http.Request) *kmsErrors.AppError {
	token, err := auth.ExtractToken(r.Context())
	if err != nil {
		return kmsErrors.NewAppError(err, "Failed to extract token", 401)
	}

	admin, appErr := h.AdminService.Me(token.Payload.Sub)
	if appErr != nil {
		return appErr
	}

	response := &dto.UserResponse{
		Email: admin.Email,
		Role: admin.Role,
	}
	
	return utils.WriteJSON(w, response)
}
