package integration

import (
	"kms/internal/api"
	"kms/internal/bootstrap"
	dbEncr "kms/internal/storage/encryption"
	"kms/internal/storage/postgres"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
)

var server *httptest.Server
var appCtx *bootstrap.AppContext

func TestMain(m *testing.M) {
	http.DefaultServeMux = http.NewServeMux()

	cfg, err := bootstrap.LoadConfig("../../../.env")
	if err != nil {
		panic(err)
	}
	keyManager, err := bootstrap.InitStaticKeyManager(cfg)
	if err != nil {
		panic(err)
	}

	consoleLogger, err := bootstrap.InitConsoleLogger(cfg["LOG_LEVEL"])
	if err != nil {
		panic(err)
	}

	db, err := bootstrap.ConnectDatabase(cfg)
	if err != nil {
		panic(err)
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
				"username":       "VARCHAR(128) UNIQUE NOT NULL",
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
		panic(err)
	}

	keyRepo := dbEncr.NewEncryptedKeyRepo(postgres.NewPostgresKeyRepo(db), keyManager)
	adminRepo := dbEncr.NewEncryptedAdminRepo(postgres.NewPostgresAdminRepo(db), keyManager)
	userRepo := dbEncr.NewEncryptedUserRepo(postgres.NewPostgresUserRepo(db), keyManager)

	// TODO: Add startup time to dismiss old JWTs
	appCtx = &bootstrap.AppContext{
		Cfg:        cfg,
		KeyManager: keyManager,
		Logger:     consoleLogger,
		DB:         db,
		UserRepo:   userRepo,
		KeyRepo:    keyRepo,
		AdminRepo:  adminRepo,
	}

	if err := api.RegisterRoutes(appCtx); err != nil {
		panic(err)
	}

	server = httptest.NewServer(nil)
	defer server.Close()

	code := m.Run()

	os.Exit(code)
}
