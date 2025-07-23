package encryption

import (
	"kms/internal/users"
	"kms/internal/admin"
	c "kms/internal/bootstrap/context"
)

type EncryptedAdminRepo struct {
	AdminRepo 	admin.AdminRepository
	KeyManager 	c.KeyManager
}

func NewEncryptedAdminRepo(adminRepo admin.AdminRepository, keyManager c.KeyManager) *EncryptedAdminRepo {
	return &EncryptedAdminRepo{
		AdminRepo: adminRepo,
		KeyManager: keyManager,
	}
}
 
func (r *EncryptedAdminRepo) GetAdmin(id int) (*users.User, error) {
	user, err := r.AdminRepo.GetAdmin(id)
	if err != nil {
		return nil, err
	}

	decUser := &users.User{}
	if err := DecryptFields(decUser, user, r.KeyManager); err != nil {
		return nil, err
	}
	return decUser, nil
}

