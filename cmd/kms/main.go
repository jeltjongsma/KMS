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

	if err := postgres.InitSchema(cfg, db, keyManager, "database/migrations"); err != nil {
		log.Fatal("Failed to init schema: ", err)
	}

	keyRepo := dbEncr.NewEncryptedKeyRepo(postgres.NewPostgresKeyRepo(db), keyManager)
	adminRepo := dbEncr.NewEncryptedAdminRepo(postgres.NewPostgresAdminRepo(db), keyManager)
	clientRepo := dbEncr.NewEncryptedClientRepo(postgres.NewPostgresClientRepo(db), keyManager)

	appCtx := &bootstrap.AppContext{
		Cfg:        cfg,
		KeyManager: keyManager,
		Logger:     consoleLogger,
		DB:         db,
		ClientRepo: clientRepo,
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
