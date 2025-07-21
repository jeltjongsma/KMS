package server

import (
	"net/http"
	"kms/server/handlers"
	"kms/server/auth"
	"kms/server/router"
	"kms/infra"
	"kms/server/services"
	"kms/server/httpkit"
	encr "kms/storage/db_encryption"
	"strconv"
	b64 "encoding/base64"
	"kms/storage/postgres"
)

// Single http.HandleFunc() with custom router?
func RegisterRoutes(ctx *infra.AppContext) error {
	// TODO: Replace with separate key
	keyRepo := encr.NewEncryptedKeyRepo(postgres.NewPostgresKeyRepo(ctx.DB), ctx.KEK)
	adminRepo := encr.NewEncryptedAdminRepo(postgres.NewPostgresAdminRepo(ctx.DB), ctx.KEK)
	userRepo := encr.NewEncryptedUserRepo(postgres.NewPostgresUserRepo(ctx.DB), ctx.KEK)
	
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

	authService := services.NewAuthService(ctx.Cfg, userRepo, jwtGenInfo, jwtSecret, ctx.KeyRefSecret)
	authHandler := handlers.NewAuthHandler(authService)

	keyService := services.NewKeyService(keyRepo, ctx.KeyRefSecret)
	keyHandler := handlers.NewKeyHandler(keyService)

	adminService := services.NewAdminService(adminRepo, userRepo, jwtSecret) 
	adminHandler := handlers.NewAdminHandler(adminService)

	userService := services.NewUserService(userRepo)
	userHandler := handlers.NewUserHandler(userService)

	var withAuth = auth.Authorize(ctx.JWTSecret) 
	var adminOnly = auth.RequireAdmin(userRepo) 

	// Register routes for dev-only environment
	if ctx.Cfg["ENV"] == "dev" {
		http.Handle("/users", httpkit.AppHandler(userHandler.GetAllDev))
		http.Handle("/keys", httpkit.AppHandler(keyHandler.GetAllDev))
	}

	http.Handle("/keys/", router.MakeRouter(
		[]*router.Route{
			router.NewRoute(
				"POST",
				"/keys/generate",
				withAuth(keyHandler.GenerateKey),
			),
			router.NewRoute(
				"GET",
				"/keys/{keyReference}",
				withAuth(keyHandler.GetKey),
			),
		},
	))

	// Auth
	http.Handle("/auth/", router.MakeRouter(
		[]*router.Route{
			router.NewRoute(
				"POST",
				"/auth/signup",
				authHandler.Signup,
			),
			router.NewRoute(
				"POST",
				"/auth/login",
				authHandler.Login,
			),
		},
	))

	// Users
	http.Handle("/users/", router.MakeRouter(
		[]*router.Route{
			router.NewRoute(
				"POST",
				"/users/{id}/role",
				withAuth(adminOnly(adminHandler.UpdateRole)),
			),
			router.NewRoute(
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
