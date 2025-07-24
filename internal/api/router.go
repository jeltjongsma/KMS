package api

import (
	"net/http"
	"strconv"
	"kms/internal/bootstrap"
	"kms/internal/users"
	"kms/internal/admin"
	"kms/internal/keys"
	"kms/internal/auth"
	mw "kms/internal/api/middleware"
	"kms/internal/httpctx"
)

// Single http.HandleFunc() with custom router?
func RegisterRoutes(ctx *bootstrap.AppContext) error {
	// TODO: Clean this mess
	
	jwtTtl, err := strconv.ParseInt(ctx.Cfg["JWT_TTL"], 0, 64)
	if err != nil {
		return err
	}

	jwtGenInfo := &auth.TokenGenInfo{
		Ttl: jwtTtl,
		Secret: ctx.KeyManager.JWTKey(),
		Typ: "jwt",
	}

	authService := auth.NewService(ctx.Cfg, ctx.UserRepo, jwtGenInfo, ctx.KeyManager, ctx.Logger)
	authHandler := auth.NewHandler(authService, ctx.Logger)

	keyService := keys.NewService(ctx.KeyRepo, ctx.KeyManager, ctx.Logger)
	keyHandler := keys.NewHandler(keyService, ctx.Logger)

	adminService := admin.NewService(ctx.AdminRepo, ctx.UserRepo, ctx.KeyManager, ctx.Logger) 
	adminHandler := admin.NewHandler(adminService, ctx.Logger)

	userService := users.NewService(ctx.UserRepo, ctx.Logger)
	userHandler := users.NewHandler(userService, ctx.Logger)

	var withAuth = mw.Authorize(ctx.KeyManager.JWTKey()) 
	var adminOnly = mw.RequireAdmin(ctx.UserRepo) 
	var wrapHandler = httpctx.WrapAppHandler(ctx.Logger)

	// Register routes for dev-only environment
	if ctx.Cfg["ENV"] == "dev" {
		http.Handle("/users", wrapHandler(httpctx.AppHandler(userHandler.GetAllDev)))
		http.Handle("/keys", wrapHandler(httpctx.AppHandler(keyHandler.GetAllDev)))
	}

	http.Handle("/keys/", wrapHandler(mw.MakeRouter(
		[]*mw.Route{
			mw.NewRoute(
				"POST",
				"/keys/generate",
				withAuth(keyHandler.GenerateKey),
			),
			mw.NewRoute(
				"GET",
				"/keys/{keyReference}",
				withAuth(keyHandler.GetKey),
			),
		},
	)))

	// Auth
	http.Handle("/auth/", wrapHandler(mw.MakeRouter(
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
	http.Handle("/users/", wrapHandler(mw.MakeRouter(
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
		},
	)))

	// Admin
	http.Handle("/admin", wrapHandler(withAuth(adminOnly(adminHandler.Me))))
	
	return nil
}
