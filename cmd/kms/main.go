package main

import (
	"net/http"
	"log"
	"fmt"
	"kms/internal/bootstrap"
	"kms/internal/storage/postgres"
	"kms/internal/api"
	dbEncr "kms/internal/storage/encryption"
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
		log.Fatal("Unable to initialise loggerL ", err)
	}

	db, err := bootstrap.ConnectDatabase(cfg)
	if err != nil {
		log.Fatal("Unable to connect to database: ", err)
	}
	defer db.Close()

	// TODO: Implement migration instead of this mess
	schemas := []postgres.TableSchema{
		postgres.TableSchema{
			Name: "keys",
			Fields: map[string]string{
				"id": "SERIAL PRIMARY KEY",
				"keyReference": "TEXT",
				"dek": 	"TEXT",
				"userId": "INT",
				"encoding": "TEXT",
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
		postgres.TableSchema{
			Name: "users",
			Fields: map[string]string{
				"id": "SERIAL PRIMARY KEY",
				"username": "TEXT UNIQUE NOT NULL",
				"hashedUsername": "TEXT UNIQUE NOT NULL",
				"password": "TEXT NOT NULL",
				"role": "TEXT NOT NULL DEFAULT 'user'",
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
		Cfg: cfg,
		KeyManager: keyManager,
		Logger: consoleLogger,
		DB: db,
		UserRepo: userRepo,
		KeyRepo: keyRepo,
		AdminRepo: adminRepo,
	}

	if err := api.RegisterRoutes(appCtx); err != nil {
		log.Fatal("Unable to register routes: ", err)
	}

	http.ListenAndServe(fmt.Sprintf(":%v", cfg["SERVER_PORT"]), nil)
}