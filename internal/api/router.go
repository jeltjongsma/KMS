package api

import (
	"kms/internal/admin"
	mw "kms/internal/api/middleware"
	"kms/internal/auth"
	"kms/internal/bootstrap"
	"kms/internal/httpctx"
	"kms/internal/keys"
	"net/http"
	"strconv"
)

// Single http.HandleFunc() with custom router?
func RegisterRoutes(ctx *bootstrap.AppContext) error {
	jwtTtl, err := strconv.ParseInt(ctx.Cfg["JWT_TTL"], 0, 64)
	if err != nil {
		return err
	}

	jwtGenInfo := &auth.TokenGenInfo{
		Ttl:    jwtTtl,
		Secret: ctx.KeyManager.JWTKey(),
		Typ:    "jwt",
	}

	authService := auth.NewService(ctx.Cfg, ctx.UserRepo, jwtGenInfo, ctx.KeyManager, ctx.Logger)
	authHandler := auth.NewHandler(authService, ctx.Logger)

	keyService := keys.NewService(ctx.KeyRepo, ctx.KeyManager, ctx.Logger)
	keyHandler := keys.NewHandler(keyService, ctx.Logger)

	adminService := admin.NewService(ctx.AdminRepo, ctx.UserRepo, ctx.KeyManager, ctx.Logger)
	adminHandler := admin.NewHandler(adminService, ctx.Logger)

	// userService := users.NewService(ctx.UserRepo, ctx.Logger)
	// userHandler := users.NewHandler(userService, ctx.Logger)

	var withAuth = mw.Authorize(ctx.KeyManager.JWTKey())
	var adminOnly = mw.RequireAdmin(ctx.UserRepo)
	var globalHandler = httpctx.GlobalAppHandler(ctx.Logger)

	// Register routes for dev-only environment
	if ctx.Cfg["ENV"] == "dev" {
		// http.Handle("/users", globalHandler(httpctx.AppHandler(userHandler.GetAllDev)))
		http.Handle("/keys", globalHandler(httpctx.AppHandler(keyHandler.GetAllDev)))
	}

	http.Handle("/keys/", globalHandler(mw.MakeRouter(
		[]*mw.Route{
			mw.NewRoute(
				"POST",
				"/keys/actions/generate",
				withAuth(keyHandler.GenerateKey),
			),
			mw.NewRoute(
				"GET",
				"/keys/{keyReference}",
				withAuth(keyHandler.GetKey),
			),
			mw.NewRoute(
				"PATCH",
				"/keys/{keyReference}/renew",
				withAuth(keyHandler.RenewKey),
			),
		},
	)))

	// Auth
	http.Handle("/auth/", globalHandler(mw.MakeRouter(
		[]*mw.Route{
			mw.NewRoute(
				"POST",
				"/auth/signup",
				authHandler.Signup,
			),
			mw.NewRoute(
				"POST",
				"/auth/login",
				authHandler.Login,
			),
		},
	)))

	// Users
	http.Handle("/users/", globalHandler(mw.MakeRouter(
		[]*mw.Route{
			mw.NewRoute(
				"POST",
				"/users/{id}/role",
				withAuth(adminOnly(adminHandler.UpdateRole)),
			),
			mw.NewRoute(
				"POST",
				"/users/tokens/generate",
				withAuth(adminOnly(adminHandler.GenerateSignupToken)),
			),
			mw.NewRoute(
				"GET",
				"/users",
				withAuth(adminOnly(adminHandler.GetUsers)),
			),
			// mw.NewRoute(
			// 	"DELETE",
			// 	"/users/{id}",
			// 	withAuth(adminOnly(adminHandler.DeleteUser)),
			// ),
		},
	)))

	// Admin
	http.Handle("/admin", globalHandler(withAuth(adminOnly(adminHandler.Me))))

	return nil
}
