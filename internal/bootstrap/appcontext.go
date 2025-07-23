package bootstrap

import (
	"database/sql"
	"kms/internal/keys"
	"kms/internal/users"
	"kms/internal/admin"
	c "kms/internal/bootstrap/context"
)

type AppContext struct {
	Cfg		 		c.KmsConfig
	KeyManager		c.KeyManager
	DB 				*sql.DB
	KeyRepo 		keys.KeyRepository
	UserRepo		users.UserRepository
	AdminRepo 		admin.AdminRepository
}