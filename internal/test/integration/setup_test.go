package integration

import (
	"flag"
	"kms/internal/api"
	"kms/internal/bootstrap"
	dbEncr "kms/internal/storage/encryption"
	"kms/internal/storage/postgres"
	"kms/internal/test"
	"net/http"
	"net/http/httptest"
	"os"
	"slices"
	"testing"
)

var server *httptest.Server
var appCtx *bootstrap.AppContext

func TestMain(m *testing.M) {
	flag.Parse()
	// don't run integration tests when short flag is set
	if testing.Short() {
		os.Exit(0)
	}

	http.DefaultServeMux = http.NewServeMux()

	cfg, err := bootstrap.LoadConfig("../../../.env")
	if err != nil {
		panic(err)
	}
	// set log level to debug for tests always
	cfg["LOG_LEVEL"] = "debug"

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

	if err := postgres.InitSchema(cfg, db, keyManager, "test_migrations"); err != nil {
		panic(err)
	}

	keyRepo := dbEncr.NewEncryptedKeyRepo(postgres.NewPostgresKeyRepo(db), keyManager)
	adminRepo := dbEncr.NewEncryptedAdminRepo(postgres.NewPostgresAdminRepo(db), keyManager)
	clientRepo := dbEncr.NewEncryptedClientRepo(postgres.NewPostgresClientRepo(db), keyManager)

	// TODO: Add startup time to dismiss old JWTs
	appCtx = &bootstrap.AppContext{
		Cfg:        cfg,
		KeyManager: keyManager,
		Logger:     consoleLogger,
		DB:         db,
		ClientRepo: clientRepo,
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

func TestMethodNotAllowed(t *testing.T) {
	methods := []string{"CONNECT", "GET", "POST", "PATCH", "PUT", "OPTIONS", "DELETE", "HEAD", "TRACE"}

	tests := []struct {
		path           string
		allowedMethods []string
	}{
		{"/keys/actions/generate", []string{"POST"}},
		{"/keys/keyRef/1", []string{"GET"}},
		{"/keys/keyRef/actions/rotate", []string{"POST"}},
		{"/keys/keyRef/actions/delete", []string{"DELETE"}},
		{"/auth/signup", []string{"POST"}},
		{"/auth/login", []string{"POST"}},
		{"/auth/signup/generate", []string{"POST"}},
		{"/clients/12/role", []string{"POST"}},
		{"/clients/12", []string{"DELETE"}},
	}

	for _, tt := range tests {
		for _, m := range methods {
			if slices.Contains(tt.allowedMethods, m) {
				continue
			}
			resp, err := doRequest(m, tt.path, "")
			requireReqNotFailed(t, err)
			defer resp.Body.Close()

			requireStatusCode(t, resp.StatusCode, 405)
			if m != "HEAD" {
				test.RequireContains(t, GetBody(resp), "Method not allowed")
			}
		}
	}
}
