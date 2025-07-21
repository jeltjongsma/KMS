package db_encryption

import (
	"kms/storage"
)

type EncryptedUserRepo struct {
	UserRepo 	storage.UserRepository
	Key			[]byte
}

func NewEncryptedUserRepo(userRepo storage.UserRepository, key []byte) *EncryptedUserRepo {
	return &EncryptedUserRepo{
		UserRepo: userRepo,
		Key: key,
	}
}

func (r *EncryptedUserRepo) CreateUser(user *storage.User) (int, error) {
	encUser := &storage.User{}
	if err := EncryptFields(encUser, user, r.Key); err != nil {
		return 0, err
	}
	id, err := r.UserRepo.CreateUser(encUser)
	if err != nil {
		return 0, err
	}
	return id, nil
}

func (r *EncryptedUserRepo) GetUser(id int) (*storage.User, error) {
	user, err := r.UserRepo.GetUser(id)
	if err != nil {
		return nil, err
	}
	decUser := &storage.User{}
	if err := DecryptFields(decUser, user, r.Key); err != nil {
		return nil, err
	}
	return decUser, nil
}

// Dev
func (r *EncryptedUserRepo) GetAll() ([]storage.User, error) {
	return r.UserRepo.GetAll()
}

func (r *EncryptedUserRepo) FindByHashedUsername(email string) (*storage.User, error) {
	user, err := r.UserRepo.FindByHashedUsername(email)
	if err != nil {
		return nil, err
	}
	decUser := &storage.User{}
	if err := DecryptFields(decUser, user, r.Key); err != nil {
		return nil, err
	}
	return decUser, nil
}

func (r *EncryptedUserRepo) UpdateRole(id int, role string) error {
	encRole, err := EncryptString(role, r.Key)
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
	role, err := DecryptString(encRole, r.Key)
	if err != nil {
		return "", err
	}
	return role, nil
}
