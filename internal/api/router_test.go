package api

import (
	"kms/internal/bootstrap"
	c "kms/internal/bootstrap/context"
	"testing"
)

func TestRouter_InvalidJWTTTL(t *testing.T) {
	cfg := c.KmsConfig(map[string]string{
		"JWT_TTL": "invalid", // Invalid TTL
	})

	ctx := &bootstrap.AppContext{
		Cfg: cfg,
	}
	err := RegisterRoutes(ctx)
	if err == nil {
		t.Error("expected error for invalid JWT_TTL, got nil")
	}
}
