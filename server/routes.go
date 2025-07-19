package server

import (
	"net/http"
	"kms/server/handlers"
	"kms/server/auth"
	"kms/server/router"
	"kms/infra"
	"kms/server/services"
	"kms/server/httpkit"
)

// TODO: Single http.HandleFunc() with custom router?
func RegisterRoutes(cfg infra.KmsConfig, ctx *infra.AppContext) {
	var withAuth = auth.Authorize(ctx.JWTSecret) 
	var adminOnly = auth.RequireAdmin(ctx.UserRepo) 

	keyService := services.NewKeyService(ctx.KeyRepo)
	keyHandler := handlers.NewKeyHandler(keyService)

	authService := services.NewAuthService(ctx.Cfg, ctx.UserRepo)
	authHandler := handlers.NewAuthHandler(authService)

	adminService := services.NewAdminService(ctx.AdminRepo, ctx.UserRepo) 
	adminHandler := handlers.NewAdminHandler(adminService)

	// Register routes for dev only environment
	if cfg["ENV"] == "dev" {
		http.HandleFunc("/users", handlers.MakeUserHandler(ctx.UserRepo))
		http.HandleFunc("/keys", handlers.MakeKeyHandler(ctx.KeyRepo))
	}

	http.Handle("/keys/", router.MakeRouter(
		[]*router.Route{
			router.NewRoute(
				"POST",
				"/keys/generate",
				httpkit.AppHandler(withAuth(keyHandler.GenerateKey)),
			),
			router.NewRoute(
				"GET",
				"/keys/{keyReference}",
				httpkit.AppHandler(withAuth(keyHandler.GetKey)),
			),
		},
	))

	// Auth
	http.Handle("/auth/", router.MakeRouter(
		[]*router.Route{
			router.NewRoute(
				"POST",
				"/auth/signup",
				httpkit.AppHandler(authHandler.Signup),
			),
			router.NewRoute(
				"POST",
				"/auth/login",
				httpkit.AppHandler(authHandler.Login),
			),
		},
	))

	// Users
	http.Handle("/users/", router.MakeRouter(
		[]*router.Route{
			router.NewRoute(
				"POST",
				"/users/{id}/role",
				httpkit.AppHandler(withAuth(adminOnly(adminHandler.UpdateRole))),
			),
		},
	))

	// Admin
	http.Handle("/admin", httpkit.AppHandler(withAuth(adminOnly(adminHandler.Me))))
	// http.HandleFunc("/admin", withAuth(adminOnly(handlers.MakeAdminHandler(ctx.AdminRepo))))
}
