package bootstrap

import (
	"database/sql"
	"kms/internal/admin"
	c "kms/internal/bootstrap/context"
	"kms/internal/clients"
	"kms/internal/keys"
)

type AppContext struct {
	Cfg        c.KmsConfig
	KeyManager c.KeyManager
	Logger     c.Logger
	DB         *sql.DB
	KeyRepo    keys.KeyRepository
	ClientRepo clients.ClientRepository
	AdminRepo  admin.AdminRepository
}
