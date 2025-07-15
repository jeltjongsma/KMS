package server

import (
	"net/http"
	"kms/server/handlers"
	"kms/storage"
)

func RegisterRoutes(keyRepo storage.KeyRepository, userRepo storage.UserRepository) {
	http.HandleFunc("/keys", handlers.MakeKeyHandler(keyRepo))
	http.HandleFunc("/keys/", handlers.MakeKeyByIDHandler(keyRepo))

	http.HandleFunc("/auth/signup", handlers.MakeSignupHandler(userRepo))
	http.HandleFunc("/auth/login", handlers.MakeLoginHandler(userRepo))

	http.HandleFunc("/users", handlers.MakeUserHandler(userRepo))
	http.HandleFunc("/users/", handlers.MakeUserByIDHandler(userRepo))
}