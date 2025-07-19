package handlers

import (
	"kms/storage"
	"net/http"
	"kms/utils"
)

// Dev only
func MakeUserHandler(userRepo storage.UserRepository) http.HandlerFunc {
	return func (w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			users, err := userRepo.GetAll()
			if utils.HandleRepoErr(w, err, "Failed to retrieve users") {return}

			utils.SendEncodedJSON(w, users)
			return

		default:
			utils.ReturnMethodNotAllowed(w)
		}
	}
}
