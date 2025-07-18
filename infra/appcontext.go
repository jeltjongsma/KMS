package infra

import (
	"kms/storage"
)

type AppContext struct {
	Cfg 		KmsConfig
	JWTSecret 	[]byte
	KEK			[]byte
	KeyRepo 	storage.KeyRepository
	UserRepo	storage.UserRepository
	AdminRepo	storage.AdminRepository
}