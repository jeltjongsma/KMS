package bootstrap

import (
	"database/sql"
	"kms/internal/admin"
	c "kms/internal/bootstrap/context"
	"kms/internal/keys"
	"kms/internal/users"
)

type AppContext struct {
	Cfg        c.KmsConfig
	KeyManager c.KeyManager
	Logger     c.Logger
	DB         *sql.DB
	KeyRepo    keys.KeyRepository
	UserRepo   users.UserRepository
	AdminRepo  admin.AdminRepository
}
