package handlers

import (
	"net/http"
	"database/sql"
	"kms/storage"
	"kms/utils"
	"errors"
)

func MakeKeyHandler(repo storage.KeyRepository) http.HandlerFunc {
	return func (w http.ResponseWriter, r *http.Request) {
		switch r.Method {

		// TODO: Discard invalid request body
		case http.MethodPost:
			defer r.Body.Close()

			var newKey storage.Key
			if utils.HandleHttpErr(w, utils.DecodePayload(r.Body, &newKey), 
					"Invalid request body", http.StatusBadRequest) {
				return
			}

			id, err := repo.CreateKey(&newKey)
			newKey.ID = id

			// TODO: Perform error handling different (Global handler?)
			if errors.Is(err, sql.ErrNoRows) {
				http.Error(w, "User not found", http.StatusNotFound)
			}
			utils.HandleErr(err, "Could not query row")

			w.Header().Set("Content-Type", "application/json")
			utils.SendEncodedJSON(w, &newKey)
			return

		case http.MethodGet:
			keys, err := repo.GetAll()
			if utils.HandleHttpErr(w, err, "Failed to retrieve keys", http.StatusInternalServerError) {return}

			w.Header().Set("Content-Type", "application/json")
			utils.SendEncodedJSON(w, keys)
			return

		default:
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		}
	}
}

func MakeKeyByIDHandler(repo storage.KeyRepository) http.HandlerFunc {
	return func (w http.ResponseWriter, r *http.Request) {
		id, err := utils.GetIDFromURL(r.URL.Path, 2, true)
		if utils.HandleHttpErr(w, err, "Couldn't retrieve ID from URL", http.StatusBadRequest) {return}

		switch r.Method {
		case http.MethodGet:
			key, err := repo.GetKey(id)
			if utils.HandleHttpErr(w, err, "Failed to retrieve key", http.StatusNotFound) {return}

			w.Header().Set("Content-Type", "application/json")
			utils.SendEncodedJSON(w, &key)
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