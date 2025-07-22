package api

import (
	"net/http"
	"strconv"
	b64 "encoding/base64"
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
	// TODO: Replace with separate key
	// TODO: Clean this mess
	
	jwtTtl, err := strconv.ParseInt(ctx.Cfg["JWT_TTL"], 0, 64)
	if err != nil {
		return err
	}

	jwtSecret, err := b64.RawURLEncoding.DecodeString(ctx.Cfg["JWT_SECRET"])
	if err != nil {
		return err
	}

	jwtGenInfo := &auth.TokenGenInfo{
		Ttl: jwtTtl,
		Secret: jwtSecret,
		Typ: "jwt",
	}

	authService := auth.NewService(ctx.Cfg, ctx.UserRepo, jwtGenInfo, jwtSecret, ctx.KeyRefSecret)
	authHandler := auth.NewHandler(authService)

	keyService := keys.NewService(ctx.KeyRepo, ctx.KeyRefSecret)
	keyHandler := keys.NewHandler(keyService)

	adminService := admin.NewService(ctx.AdminRepo, ctx.UserRepo, jwtSecret) 
	adminHandler := admin.NewHandler(adminService)

	userService := users.NewService(ctx.UserRepo)
	userHandler := users.NewHandler(userService)

	var withAuth = mw.Authorize(ctx.JWTSecret) 
	var adminOnly = mw.RequireAdmin(ctx.UserRepo) 

	// Register routes for dev-only environment
	if ctx.Cfg["ENV"] == "dev" {
		http.Handle("/users", httpctx.AppHandler(userHandler.GetAllDev))
		http.Handle("/keys", httpctx.AppHandler(keyHandler.GetAllDev))
	}

	http.Handle("/keys/", mw.MakeRouter(
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
	))

	// Auth
	http.Handle("/auth/", mw.MakeRouter(
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
	))

	// Users
	http.Handle("/users/", mw.MakeRouter(
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
	))

	// Admin
	http.Handle("/admin", withAuth(adminOnly(adminHandler.Me)))
	
	return nil
}
