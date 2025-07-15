package handlers

import (
	"kms/storage"
	"net/http"
	"kms/utils"
	"kms/server/auth"
	"strconv"
)

func MakeUserHandler(userRepo storage.UserRepository) auth.AuthorizedHandlerFunc {
	return auth.AuthorizedHandlerFunc(func (w http.ResponseWriter, r *http.Request, token auth.Token) {
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
	})
}

func MakeUserByIDHandler(userRepo storage.UserRepository) http.HandlerFunc {
	return func (w http.ResponseWriter, r *http.Request) {
		idStr, err := utils.GetIDFromURL(r.URL.Path, 2, true)
		if utils.HandleErrAndSendHttp(w, err, "Couldn't retrieve ID from URL", http.StatusBadRequest) {return}

		id, err := strconv.Atoi(idStr)
		if utils.HandleErrAndSendHttp(w, err, "ID must be a number", http.StatusBadRequest) {return}
		
		switch r.Method {
		case http.MethodGet:
			user, err := userRepo.GetUser(id)
			if utils.HandleRepoErr(w, err, "Failed to retrieve user") {return}
			
			utils.SendEncodedJSON(w, user)
			return

		case http.MethodPut:
			http.Error(w, "", http.StatusNotImplemented)
		case http.MethodDelete:
			http.Error(w, "", http.StatusNotImplemented)
		default:
			utils.ReturnMethodNotAllowed(w)
		}
	}
}