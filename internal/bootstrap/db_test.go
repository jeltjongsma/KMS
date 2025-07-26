package bootstrap

import (
	c "kms/internal/bootstrap/context"
	"testing"
)

func TestConnectDatabase_InvalidConfig(t *testing.T) {
	cfg := c.KmsConfig{
		"DB_PORT":     "5432",
		"DB_USER":     "invalid_user",
		"DB_PASSWORD": "invalid_pass",
		"DB_NAME":     "invalid_db",
		"DB_SSLMODE":  "disable",
	}

	db, err := ConnectDatabase(cfg)
	if err == nil {
		t.Error("Expected error when connecting with invalid config, got nil")
	}
	if db == nil {
		t.Error("Expected non-nil *sql.DB even on error, got nil")
	}
}
