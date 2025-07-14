package handlers

import (
	"net/http"
	"kms/storage"
	"kms/utils"
	"errors"
	"database/sql"
)

func MakeKeyHandler(db *sql.DB) http.HandlerFunc {
	return func (w http.ResponseWriter, r *http.Request) {
		switch r.Method {

		case http.MethodPost:
			defer r.Body.Close()

			var newKey storage.Key
			if utils.HandleHttpErr(w, utils.DecodePayload(r.Body, &newKey), 
					"Invalid request body", http.StatusBadRequest) {
				return
			}

			err := db.QueryRow(
				"INSERT INTO keys (dek, userId) VALUES ($1, $2) RETURNING id",
				&newKey.DEK, &newKey.UserId,
			).Scan(&newKey.ID)

			if errors.Is(err, sql.ErrNoRows) {
				http.Error(w, "User not found", http.StatusNotFound)
			}
			utils.HandleErr(err, "Could not query row")

			w.Header().Set("Content-Type", "application/json")
			utils.EncodeJSON(w, &newKey)
			return

		case http.MethodGet:
			rows, err := db.Query(
				"SELECT * FROM keys",
			)
			utils.HandleErr(err, "Failed to query keys")

			var keys []storage.Key
			defer rows.Close()
			for rows.Next() {
				var key storage.Key
				err := rows.Scan(&key.ID, &key.DEK, &key.UserId)
				utils.HandleErr(err, "Failed to read row")
				keys = append(keys, key)
			}

			w.Header().Set("Content-Type", "application/json")
			utils.EncodeJSON(w, keys)
			return

		default:
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		}
	}
}

func MakeKeyByIDHandler(db *sql.DB) http.HandlerFunc {
	return func (w http.ResponseWriter, r *http.Request) {
		id, err := utils.GetIDFromURL(r.URL.Path, 2, true)
		if utils.HandleHttpErr(w, err, "Couldn't retrieve ID from URL", http.StatusBadRequest) {
			return
		}
		switch r.Method {
		case http.MethodGet:
			row := db.QueryRow(
				"SELECT * FROM keys WHERE id = $1",
				id,
			)

			var key storage.Key
			err := row.Scan(&key.ID, &key.DEK, &key.UserId)
			if utils.HandleHttpErr(w, err, "Failed to retrieve key", http.StatusNotFound) {
				return
			}

			w.Header().Set("Content-Type", "application/json")
			utils.EncodeJSON(w, &key)
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