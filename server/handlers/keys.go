package handlers

import (
	"net/http"
	"kms/storage"
	"kms/utils"
)

func MakeKeyHandler(keyRepo storage.KeyRepository) http.HandlerFunc {
	return func (w http.ResponseWriter, r *http.Request) {
		switch r.Method {

		// TODO: Discard invalid request body
		case http.MethodPost:
			var newKey storage.Key
			if utils.DecodePayloadAndHandleError(w, r.Body, &newKey) {return}

			id, err := keyRepo.CreateKey(&newKey)
			if utils.HandleRepoErr(w, err, "Failed to create key") {return}

			newKey.ID = id

			utils.SendEncodedJSON(w, &newKey)

		case http.MethodGet:
			keys, err := keyRepo.GetAll()
			if utils.HandleErrAndSendHttp(w, err, "Failed to retrieve keys", http.StatusInternalServerError) {return}

			utils.SendEncodedJSON(w, keys)
			return

		default:
			utils.ReturnMethodNotAllowed(w)
		}
	}
}

func MakeKeyByIDHandler(keyRepo storage.KeyRepository) http.HandlerFunc {
	return func (w http.ResponseWriter, r *http.Request) {
		id, err := utils.GetIDFromURL(r.URL.Path, 2, true)
		if utils.HandleErrAndSendHttp(w, err, "Couldn't retrieve ID from URL", http.StatusBadRequest) {return}

		switch r.Method {
		case http.MethodGet:
			key, err := keyRepo.GetKey(id)
			if utils.HandleRepoErr(w, err, "Failed to retrieve key") {return}

			utils.SendEncodedJSON(w, &key)
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