package handlers

import (
	"net/http"
	"kms/server/auth"
	"kms/storage"
	"kms/utils"
)

func MakeAdminHandler(adminRepo storage.AdminRepository) http.HandlerFunc {
	return func (w http.ResponseWriter, r *http.Request) {
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