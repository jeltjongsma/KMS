package server

import (
	"net/http"
	"kms/server/handlers"
	"kms/server/auth"
	"kms/storage"
)

func RegisterRoutes(cfg map[string]string, 
			keyRepo storage.KeyRepository, 
			userRepo storage.UserRepository, 
			adminRepo storage.AdminRepository,
	) {
	// http.HandleFunc("/keys", Authorize(cfg, handlers.MakeKeyHandler(keyRepo)))
	http.HandleFunc("/keys/", handlers.MakeKeyByIDHandler(keyRepo))

	http.HandleFunc("/auth/signup", handlers.MakeSignupHandler(cfg, userRepo))
	http.HandleFunc("/auth/login", handlers.MakeLoginHandler(cfg, userRepo))

	http.HandleFunc("/users", withAuth(cfg, handlers.MakeUserHandler(userRepo)))
	http.HandleFunc("/users/", handlers.MakeUserByIDHandler(userRepo))

	http.HandleFunc("/admin", withAuth(cfg, auth.RequireAdmin(handlers.MakeAdminHandler(adminRepo))))
}

func withAuth(cfg map[string]string, next http.HandlerFunc) http.HandlerFunc {
	return auth.Authorize(cfg, next)
}