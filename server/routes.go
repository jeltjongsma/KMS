package server

import (
	"net/http"
	"kms/server/handlers"
	"kms/storage"
)

func RegisterRoutes(cfg map[string]string, keyRepo storage.KeyRepository, userRepo storage.UserRepository) {
	http.HandleFunc("/keys", handlers.MakeKeyHandler(keyRepo))
	http.HandleFunc("/keys/", handlers.MakeKeyByIDHandler(keyRepo))

	http.HandleFunc("/auth/signup", handlers.MakeSignupHandler(cfg, userRepo))
	http.HandleFunc("/auth/login", handlers.MakeLoginHandler(cfg, userRepo))

	http.HandleFunc("/users", handlers.MakeUserHandler(userRepo))
	http.HandleFunc("/users/", handlers.MakeUserByIDHandler(userRepo))
}