package server

import (
	"net/http"
	"kms/server/handlers"
	"kms/server/auth"
	"kms/server/router"
	"kms/infra"
)

func RegisterRoutes(ctx *infra.AppContext) {
	var adminOnly = auth.RequireAdmin(ctx.UserRepo) 
	var withAuth = auth.Authorize([]byte(ctx.Cfg["JWT_SECRET"]))

	// http.HandleFunc("/keys", Authorize(cfg, handlers.MakeKeyHandler(keyRepo)))
	http.HandleFunc("/keys/", handlers.MakeKeyByIDHandler(ctx.KeyRepo))

	// Auth
	http.HandleFunc("/auth/signup", handlers.MakeSignupHandler(ctx.Cfg, ctx.UserRepo))
	http.HandleFunc("/auth/login", handlers.MakeLoginHandler(ctx.Cfg, ctx.UserRepo))

	// Users
	http.HandleFunc("/users", withAuth(handlers.MakeUserHandler(ctx.UserRepo)))
	http.HandleFunc("/users/", router.MakeRouter(
		[]*router.Route{
			router.NewRoute(
				"POST", 
				"/users/{id}/role", 
				withAuth(adminOnly(handlers.MakeUserRoleHandler(ctx.UserRepo))),
			),
		},
	))
	// http.HandleFunc("/users/", handlers.MakeUserByIDHandler(ctx.UserRepo))

	// Admin
	http.HandleFunc("/admin", withAuth(adminOnly(handlers.MakeAdminHandler(ctx.AdminRepo))))
	// http.HandleFunc("/admin/", withAuth(ctx.Cfg, auth.RequireAdmin(handlers.MakeAdmin)))
}
