package encryption

import (
	"kms/internal/users"
	"kms/internal/admin"
)

type EncryptedAdminRepo struct {
	AdminRepo 	admin.AdminRepository
	Key 		[]byte
}

func NewEncryptedAdminRepo(adminRepo admin.AdminRepository, key []byte) *EncryptedAdminRepo {
	return &EncryptedAdminRepo{
		AdminRepo: adminRepo,
		Key: key,
	}
}
 
func (r *EncryptedAdminRepo) GetAdmin(id int) (*users.User, error) {
	user, err := r.AdminRepo.GetAdmin(id)
	if err != nil {
		return nil, err
	}

	decUser := &users.User{}
	if err := DecryptFields(decUser, user, r.Key); err != nil {
		return nil, err
	}
	return decUser, nil
}

