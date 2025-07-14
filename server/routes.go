package server

import (
	"net/http"
	"kms/server/handlers"
	"kms/storage"
)

func RegisterRoutes(repo storage.KeyRepository) {

	http.HandleFunc("/keys", handlers.MakeKeyHandler(repo))
	http.HandleFunc("/keys/", handlers.MakeKeyByIDHandler(repo))
}