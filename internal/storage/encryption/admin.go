package encryption

import (
	"kms/internal/admin"
	c "kms/internal/bootstrap/context"
	"kms/internal/clients"
)

type EncryptedAdminRepo struct {
	AdminRepo  admin.AdminRepository
	KeyManager c.KeyManager
}

func NewEncryptedAdminRepo(adminRepo admin.AdminRepository, keyManager c.KeyManager) *EncryptedAdminRepo {
	return &EncryptedAdminRepo{
		AdminRepo:  adminRepo,
		KeyManager: keyManager,
	}
}

func (r *EncryptedAdminRepo) GetAdmin(id int) (*clients.Client, error) {
	client, err := r.AdminRepo.GetAdmin(id)
	if err != nil {
		return nil, err
	}

	decClient := &clients.Client{}
	if err := DecryptFields(decClient, client, r.KeyManager); err != nil {
		return nil, err
	}
	return decClient, nil
}
