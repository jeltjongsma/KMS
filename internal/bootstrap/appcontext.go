package bootstrap

import (
	"database/sql"
	"kms/internal/keys"
	"kms/internal/users"
	"kms/internal/admin"
	t "kms/internal/types"
)

type AppContext struct {
	Cfg		 		t.KmsConfig
	JWTSecret 		[]byte
	KEK				[]byte
	KeyRefSecret	[]byte
	DB 				*sql.DB
	KeyRepo 		keys.KeyRepository
	UserRepo		users.UserRepository
	AdminRepo 		admin.AdminRepository
}