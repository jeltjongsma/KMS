package encryption

import (
	c "kms/internal/bootstrap/context"
	"kms/internal/users"
)

type EncryptedUserRepo struct {
	UserRepo   users.UserRepository
	KeyManager c.KeyManager
}

func NewEncryptedUserRepo(userRepo users.UserRepository, keyManager c.KeyManager) *EncryptedUserRepo {
	return &EncryptedUserRepo{
		UserRepo:   userRepo,
		KeyManager: keyManager,
	}
}

func (r *EncryptedUserRepo) CreateUser(user *users.User) (int, error) {
	encUser := &users.User{}
	if err := EncryptFields(encUser, user, r.KeyManager); err != nil {
		return 0, err
	}
	id, err := r.UserRepo.CreateUser(encUser)
	if err != nil {
		return 0, err
	}
	return id, nil
}

func (r *EncryptedUserRepo) GetUser(id int) (*users.User, error) {
	user, err := r.UserRepo.GetUser(id)
	if err != nil {
		return nil, err
	}
	decUser := &users.User{}
	if err := DecryptFields(decUser, user, r.KeyManager); err != nil {
		return nil, err
	}
	return decUser, nil
}

func (r *EncryptedUserRepo) GetAll() ([]users.User, error) {
	stored, err := r.UserRepo.GetAll()
	if err != nil {
		return nil, err
	}

	decUsers := make([]users.User, len(stored))
	for idx, u := range stored {
		decU := &users.User{}
		if err := DecryptFields(decU, &u, r.KeyManager); err != nil {
			return nil, err
		}
		decUsers[idx] = *decU
	}

	return decUsers, nil
}

func (r *EncryptedUserRepo) FindByHashedUsername(email string) (*users.User, error) {
	user, err := r.UserRepo.FindByHashedUsername(email)
	if err != nil {
		return nil, err
	}
	decUser := &users.User{}
	if err := DecryptFields(decUser, user, r.KeyManager); err != nil {
		return nil, err
	}
	return decUser, nil
}

func (r *EncryptedUserRepo) UpdateRole(id int, role string) error {
	encRole, err := EncryptString(role, r.KeyManager.DBKey())
	if err != nil {
		return err
	}
	return r.UserRepo.UpdateRole(id, encRole)
}

func (r *EncryptedUserRepo) GetRole(id int) (string, error) {
	encRole, err := r.UserRepo.GetRole(id)
	if err != nil {
		return "", err
	}
	role, err := DecryptString(encRole, r.KeyManager.DBKey())
	if err != nil {
		return "", err
	}
	return role, nil
}
