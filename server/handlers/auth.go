package handlers

import (
	"kms/storage"
	"kms/utils"
	"kms/utils/hashing"
	"kms/server/dto"
	"net/http"
	"kms/server/auth"
)

// TODO: Minimum password requirements
func MakeSignupHandler(cfg map[string]string, userRepo storage.UserRepository) http.HandlerFunc {
	return func (w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodPost:
			var cred dto.Credentials
			if utils.DecodePayloadAndHandleError(w, r.Body, &cred) {return}
			if utils.HandleErrAndSendHttp(
				w,
				cred.Validate(),
				"Missing credentials",
				http.StatusBadRequest,
			) {return}

			hashedPassword, err := hashing.HashPassword(cred.Password)
			if utils.HandleErrAndSendHttp(w, err, "Unable to hash password", http.StatusInternalServerError) {return}

			user := cred.Lift()

			user.Password = hashedPassword
			
			id, err := userRepo.CreateUser(&user)
			if utils.HandleRepoErr(w, err, "Failed to create user") {return}

			user.ID = id

			jwt, err := auth.GenerateJWT(cfg, user.ID)
			if utils.HandleErrAndSendHttp(w, err, "Failed to generate JWT", http.StatusInternalServerError) {return}

			response := &dto.JWTResponse{
				JWT: jwt,
			}

			utils.SendEncodedJSON(w, response)
			return

		default:
			utils.ReturnMethodNotAllowed(w)
		}
	}
}

func MakeLoginHandler(cfg map[string]string, userRepo storage.UserRepository) http.HandlerFunc {
	return func (w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodPost:
			var cred dto.Credentials
			if utils.DecodePayloadAndHandleError(w, r.Body, &cred) {return}
			if utils.HandleErrAndSendHttp(
				w,
				cred.Validate(),
				"Missing credentials",
				http.StatusBadRequest,
			) {return}

			user, err := userRepo.FindByEmail(cred.Email)
			if utils.HandleRepoErr(w, err, "Failed to retrieve user") {return}

			if utils.HandleErrAndSendHttp(
				w, 
				hashing.CheckPassword(user.Password, cred.Password),
				"Incorrect password",
				http.StatusUnauthorized,
			) {return}

			// Return token
			// w.WriteHeader(200)
			jwt, err := auth.GenerateJWT(cfg, user.ID)
			if utils.HandleErrAndSendHttp(w, err, "Failed to generate JWT", http.StatusInternalServerError) {return}

			response := &dto.JWTResponse{
				JWT: jwt,
			}

			utils.SendEncodedJSON(w, response)
			return

		default:
			utils.ReturnMethodNotAllowed(w)
		}
	}
}