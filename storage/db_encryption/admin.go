package db_encryption

import (
	"kms/storage"
)

type EncryptedAdminRepo struct {
	AdminRepo 	storage.AdminRepository
	Key 		[]byte
}

func NewEncryptedAdminRepo(adminRepo storage.AdminRepository, key []byte) *EncryptedAdminRepo {
	return &EncryptedAdminRepo{
		AdminRepo: adminRepo,
		Key: key,
	}
}
 
func (r *EncryptedAdminRepo) GetAdmin(id int) (*storage.User, error) {
	user, err := r.AdminRepo.GetAdmin(id)
	if err != nil {
		return nil, err
	}

	decUser := &storage.User{}
	if err := DecryptFields(decUser, user, r.Key); err != nil {
		return nil, err
	}
	return decUser, nil
}

