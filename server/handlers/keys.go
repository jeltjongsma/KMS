package handlers

import (
	"net/http"
	"database/sql"
	"kms/storage"
	"kms/utils"
	"errors"
)

func MakeKeyHandler(keyRepo storage.KeyRepository) http.HandlerFunc {
	return func (w http.ResponseWriter, r *http.Request) {
		switch r.Method {

		// TODO: Discard invalid request body
		case http.MethodPost:
			var newKey storage.Key
			if utils.HandleHttpErr(w, utils.DecodePayload(r.Body, &newKey), 
					"Invalid request body", http.StatusBadRequest) {
				return
			}

			id, err := keyRepo.CreateKey(&newKey)

			// TODO: Perform error handling different (Global handler?)
			if errors.Is(err, sql.ErrNoRows) {
				http.Error(w, "Key not found", http.StatusNotFound)
			}
			if utils.HandleHttpErr(w, err, "Could not create key", http.StatusInternalServerError) {return}

			newKey.ID = id

			utils.SendEncodedJSON(w, &newKey)

		case http.MethodGet:
			keys, err := keyRepo.GetAll()
			if utils.HandleHttpErr(w, err, "Failed to retrieve keys", http.StatusInternalServerError) {return}

			utils.SendEncodedJSON(w, keys)
			return

		default:
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		}
	}
}

func MakeKeyByIDHandler(keyRepo storage.KeyRepository) http.HandlerFunc {
	return func (w http.ResponseWriter, r *http.Request) {
		id, err := utils.GetIDFromURL(r.URL.Path, 2, true)
		if utils.HandleHttpErr(w, err, "Couldn't retrieve ID from URL", http.StatusBadRequest) {return}

		switch r.Method {
		case http.MethodGet:
			key, err := keyRepo.GetKey(id)
			if utils.HandleHttpErr(w, err, "Failed to retrieve key", http.StatusNotFound) {return}

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