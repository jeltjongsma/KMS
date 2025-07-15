package handlers

import (
	"kms/storage"
	"net/http"
	"kms/utils"
	"errors"
	"database/sql"
	"strconv"
)

func MakeUserHandler(userRepo storage.UserRepository) http.HandlerFunc {
	return func (w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodPost:
			var user storage.User
			if utils.HandleHttpErr(
				w,
				utils.DecodePayload(r.Body, &user),
				"Invalid request body",
				http.StatusBadRequest,
			) {return}

			id, err := userRepo.CreateUser(&user)

			if errors.Is(err, sql.ErrNoRows) {
				http.Error(w, "User not found", http.StatusNotFound)
			}
			// TODO: Handle unique constraint differently
			if utils.HandleHttpErr(w, err, "Could not create user", http.StatusInternalServerError) {return}

			user.ID = id

			utils.SendEncodedJSON(w, &user)
			return

		case http.MethodGet:
			users, err := userRepo.GetAll()
			if utils.HandleHttpErr(w, err, "Failed to retrieve keys", http.StatusInternalServerError) {return}

			utils.SendEncodedJSON(w, users)
			return

		default:
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		}
	}
}

func MakeUserByIDHandler(userRepo storage.UserRepository) http.HandlerFunc {
	return func (w http.ResponseWriter, r *http.Request) {
		idStr, err := utils.GetIDFromURL(r.URL.Path, 2, true)
		if utils.HandleHttpErr(w, err, "Couldn't retrieve ID from URL", http.StatusBadRequest) {return}

		id, err := strconv.Atoi(idStr)
		if utils.HandleHttpErr(w, err, "ID must be a number", http.StatusBadRequest) {return}
		
		switch r.Method {
		case http.MethodGet:
			user, err := userRepo.GetUser(id)
			if utils.HandleHttpErr(w, err, "Failed to retrieve user", http.StatusNotFound) {return}
			
			utils.SendEncodedJSON(w, user)
			return

		case http.MethodPut:
			http.Error(w, "", http.StatusNotImplemented)
		case http.MethodDelete:
			http.Error(w, "", http.StatusNotImplemented)
		default:
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		}
	}
}