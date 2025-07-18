package server

import (
	"net/http"
	"kms/server/handlers"
	"kms/server/auth"
	"kms/server/router"
	"kms/infra"
)

// TODO: Single http.HandleFunc() with custom router?
func RegisterRoutes(cfg infra.KmsConfig, ctx *infra.AppContext) {
	var withAuth = auth.Authorize(ctx.JWTSecret) 
	var adminOnly = auth.RequireAdmin(ctx.UserRepo) 

	// Register routes for dev only environment
	if cfg["ENV"] == "dev" {
		http.HandleFunc("/users", handlers.MakeUserHandler(ctx.UserRepo))
		http.HandleFunc("/keys", handlers.MakeKeyHandler(ctx.KeyRepo))
	}

	http.HandleFunc("/keys/", router.MakeRouter(
		[]*router.Route{
			router.NewRoute(
				"POST",
				"/keys/generate",
				withAuth(handlers.MakeGenerateKeyHandler(ctx.KeyRepo, ctx.KEK)),
			),
			router.NewRoute(
				"GET",
				"/keys/{searchableId}",
				withAuth(handlers.MakeGetKeyHandler(ctx.KeyRepo, ctx.KEK)),
			),
		},
	))

	// Auth
	http.HandleFunc("/auth/signup", handlers.MakeSignupHandler(ctx.Cfg, ctx.UserRepo))
	http.HandleFunc("/auth/login", handlers.MakeLoginHandler(ctx.Cfg, ctx.UserRepo))

	http.HandleFunc("/users/", router.MakeRouter(
		[]*router.Route{
			router.NewRoute(
				"POST", 
				"/users/{id}/role", 
				withAuth(adminOnly(handlers.MakeUserRoleHandler(ctx.UserRepo))),
			),
		},
	))

	// Admin
	http.HandleFunc("/admin", withAuth(adminOnly(handlers.MakeAdminHandler(ctx.AdminRepo))))
}
