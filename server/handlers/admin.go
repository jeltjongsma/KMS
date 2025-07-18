package handlers

import (
	"net/http"
	"kms/server/auth"
	"kms/server/router"
	"kms/server/dto"
	"kms/storage"
	"kms/utils"
	"strconv"
)

func MakeAdminHandler(adminRepo storage.AdminRepository) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		tokenStr := r.Context().Value(auth.TokenCtxKey)
		token, ok := tokenStr.(auth.Token)
		if !ok {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}

		id := token.Payload.Sub

		admin, err := adminRepo.GetAdmin(id) 
		if utils.HandleRepoErr(w, err, "Failed to retrieve admin") {return}
		
		utils.SendEncodedJSON(w, &admin)
		return
	}
}

func MakeUserRoleHandler(userRepo storage.UserRepository) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Check if ID is valid
		userIdStr, found := router.GetRouteParam(r.Context(), "id")
		if !found {
			http.Error(w, "Failed to retrieve 'ID' from context", http.StatusInternalServerError)
		}

		userId, err := strconv.Atoi(userIdStr)
		if utils.HandleErrAndSendHttp(w, err, "ID must be integer", http.StatusBadRequest) {return}

		// Handle request
		var body dto.UpdateRoleRequest
		if utils.DecodePayloadAndHandleError(w, r.Body, &body) {return}
		if utils.HandleErrAndSendHttp(
			w, 
			body.Validate(),
			"Missing role",
			http.StatusBadRequest,
		) {return}

		if utils.HandleRepoErr(
			w, 
			userRepo.UpdateRole(userId, body.Role), 
			"Failed to update role",
		) {return}

		utils.ReturnOK(w)
	}
}