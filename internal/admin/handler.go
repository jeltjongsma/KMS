package admin

import (
	"kms/internal/api/dto"
	c "kms/internal/bootstrap/context"
	"kms/internal/httpctx"
	"kms/internal/users"
	kmsErrors "kms/pkg/errors"
	pHttp "kms/pkg/http"
	"kms/pkg/json"
	"net/http"
	"strconv"
)

type Handler struct {
	Service AdminService
	Logger  c.Logger
}

func NewHandler(adminService AdminService, logger c.Logger) *Handler {
	return &Handler{
		Service: adminService,
		Logger:  logger,
	}
}

type AdminService interface {
	UpdateRole(userId int, role string, adminId string) *kmsErrors.AppError
	Me(userId int) (*users.User, *kmsErrors.AppError)
	GenerateSignupToken(body *GenerateSignupTokenRequest, adminId string) (string, *kmsErrors.AppError)
}

func (h *Handler) UpdateRole(w http.ResponseWriter, r *http.Request) *kmsErrors.AppError {
	token, err := httpctx.ExtractToken(r.Context())
	if err != nil {
		return kmsErrors.NewInternalServerError(err)
	}

	userIdStr, err := httpctx.GetRouteParam(r.Context(), "id")
	if err != nil {
		return kmsErrors.NewInternalServerError(err)
	}

	userId, err := strconv.Atoi(userIdStr)
	if err != nil {
		return kmsErrors.NewAppError(err, "ID must be integer", 400)
	}

	var requestBody UpdateRoleRequest
	if err := json.ParseBody(r.Body, &requestBody); err != nil {
		return kmsErrors.NewAppError(err, "Invalid request body", 400)
	}

	if appErr := h.Service.UpdateRole(userId, requestBody.Role, token.Payload.Sub); appErr != nil {
		return appErr
	}

	return pHttp.WriteStatus(w, 204)
}

func (h *Handler) Me(w http.ResponseWriter, r *http.Request) *kmsErrors.AppError {
	token, err := httpctx.ExtractToken(r.Context())
	if err != nil {
		return kmsErrors.NewInternalServerError(err)
	}

	userId, err := strconv.Atoi(token.Payload.Sub)
	if err != nil {
		return kmsErrors.NewInternalServerError(err)
	}
	admin, appErr := h.Service.Me(userId)
	if appErr != nil {
		return appErr
	}

	response := &dto.UserResponse{
		Username: admin.Username,
		Role:     admin.Role,
	}

	return pHttp.WriteJSON(w, response)
}

func (h *Handler) GenerateSignupToken(w http.ResponseWriter, r *http.Request) *kmsErrors.AppError {
	adminToken, err := httpctx.ExtractToken(r.Context())
	if err != nil {
		return kmsErrors.NewInternalServerError(err)
	}

	var body GenerateSignupTokenRequest
	if err := json.ParseBody(r.Body, &body); err != nil {
		return kmsErrors.NewInvalidBodyError(err)
	}

	if err := body.Validate(); err != nil {
		return kmsErrors.NewInvalidBodyError(err)
	}

	token, appErr := h.Service.GenerateSignupToken(&body, adminToken.Payload.Sub)
	if appErr != nil {
		return appErr
	}

	response := &dto.TokenResponse{
		Token: token,
	}

	return pHttp.WriteJSON(w, response)
}
