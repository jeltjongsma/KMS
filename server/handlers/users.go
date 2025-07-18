package handlers

import (
	"kms/storage"
	"net/http"
	"kms/utils"
	"strconv"
)

func MakeUserHandler(userRepo storage.UserRepository) http.HandlerFunc {
	return func (w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodPost:
			var user storage.User
			if utils.DecodePayloadAndHandleError(w, r.Body, &user) {return}

			id, err := userRepo.CreateUser(&user)
			if utils.HandleRepoErr(w, err, "Failed to create user") {return}

			user.ID = id

			utils.SendEncodedJSON(w, &user)
			return

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
