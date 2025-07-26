package main

import (
	"errors"
	"fmt"
	"kms/internal/api"
	"kms/internal/bootstrap"
	dbEncr "kms/internal/storage/encryption"
	"kms/internal/storage/postgres"
	"log"
	"net/http"
)

func main() {
	cfg, err := bootstrap.LoadConfig(".env")
	if err != nil {
		log.Fatal("Unable to load config: ", err)
	}

	keyManager, err := bootstrap.InitStaticKeyManager(cfg)
	if err != nil {
		log.Fatal("Unable to initialise key manager: ", err)
	}

	consoleLogger, err := bootstrap.InitConsoleLogger(cfg["LOG_LEVEL"])
	if err != nil {
		log.Fatal("Unable to initialise logger: ", err)
	}

	db, err := bootstrap.ConnectDatabase(cfg)
	if err != nil {
		log.Fatal("Unable to connect to database: ", err)
	}
	defer db.Close()

	// TODO: Implement migration instead of this mess
	schemas := []postgres.TableSchema{
		{
			Name: "keys",
			Fields: map[string]string{
				"id":           "SERIAL PRIMARY KEY",
				"keyReference": "VARCHAR(64) NOT NULL",
				"dek":          "VARCHAR(80) NOT NULL",
				"userId":       "INTEGER NOT NULL",
				"encoding":     "VARCHAR(64) NOT NULL",
			},
			Keys: []string{
				"id",
				"keyReference",
				"dek",
				"userId",
				"encoding",
			},
			Unique: []string{"userId", "keyReference"},
		},
		{
			Name: "users",
			Fields: map[string]string{
				"id":             "SERIAL PRIMARY KEY",
				"username":       "VARCHAR(64) UNIQUE NOT NULL",
				"hashedUsername": "VARCHAR(44) UNIQUE NOT NULL",
				"password":       "CHAR(60) NOT NULL",
				"role":           "VARCHAR(44) NOT NULL DEFAULT 'user'",
			},
			Keys: []string{
				"id",
				"username",
				"hashedUsername",
				"password",
				"role",
			},
		},
	}

	if err := postgres.InitSchema(cfg, db, schemas, keyManager); err != nil {
		log.Fatal("Failed to create schema: ", err)
	}

	keyRepo := dbEncr.NewEncryptedKeyRepo(postgres.NewPostgresKeyRepo(db), keyManager)
	adminRepo := dbEncr.NewEncryptedAdminRepo(postgres.NewPostgresAdminRepo(db), keyManager)
	userRepo := dbEncr.NewEncryptedUserRepo(postgres.NewPostgresUserRepo(db), keyManager)

	appCtx := &bootstrap.AppContext{
		Cfg:        cfg,
		KeyManager: keyManager,
		Logger:     consoleLogger,
		DB:         db,
		UserRepo:   userRepo,
		KeyRepo:    keyRepo,
		AdminRepo:  adminRepo,
	}

	if err := api.RegisterRoutes(appCtx); err != nil {
		log.Fatal("Unable to register routes: ", err)
	}

	if err := http.ListenAndServeTLS(fmt.Sprintf(":%v", cfg["SERVER_PORT"]), "kms.crt", "kms.key", nil); err != nil && !errors.Is(err, http.ErrServerClosed) {
		log.Fatal("HTTPS server failed: ", err)
	}
}
