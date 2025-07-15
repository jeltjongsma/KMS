package handlers

import (
	"kms/storage"
	"kms/utils"
	"kms/utils/hashing"
	"net/http"
)

// TODO: Minimum password requirements
func MakeSignupHandler(userRepo storage.UserRepository) http.HandlerFunc {
	return func (w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodPost:
			var user storage.User
			if utils.DecodePayloadAndHandleError(w, r.Body, &user) {return}

			hashedPassword, err := hashing.HashPassword(user.Password)
			if utils.HandleErrAndSendHttp(w, err, "Unable to hash password", http.StatusInternalServerError) {return}

			user.Password = hashedPassword
			
			id, err := userRepo.CreateUser(&user)
			if utils.HandleRepoErr(w, err, "Failed to create user") {return}

			user.ID = id

			utils.SendEncodedJSON(w, &user)
			return

		default:
			utils.ReturnMethodNotAllowed(w)
		}
	}
}

func MakeLoginHandler(userRepo storage.UserRepository) http.HandlerFunc {
	return func (w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodPost:
			var login storage.Login
			if utils.DecodePayloadAndHandleError(w, r.Body, &login) {return}

			user, err := userRepo.FindByEmail(login.Email)
			if utils.HandleRepoErr(w, err, "Failed to retrieve user") {return}

			if utils.HandleErrAndSendHttp(
				w, 
				hashing.CheckPassword(user.Password, login.Password),
				"Incorrect password",
				http.StatusUnauthorized,
			) {return}

			// Return token
			w.WriteHeader(200)

		default:
			utils.ReturnMethodNotAllowed(w)
		}
	}
}