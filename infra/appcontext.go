package infra

import (
	"kms/storage"
)

type AppContext struct {
	Cfg 		KmsConfig
	KeyRepo 	storage.KeyRepository
	UserRepo	storage.UserRepository
	AdminRepo 	storage.AdminRepository
}