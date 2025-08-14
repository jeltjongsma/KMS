package encryption

import (
	c "kms/internal/bootstrap/context"
	"kms/internal/keys"
)

type EncryptedKeyRepo struct {
	KeyRepo    keys.KeyRepository
	KeyManager c.KeyManager
}

func NewEncryptedKeyRepo(keyRepo keys.KeyRepository, keyManager c.KeyManager) *EncryptedKeyRepo {
	return &EncryptedKeyRepo{
		KeyRepo:    keyRepo,
		KeyManager: keyManager,
	}
}

func (r *EncryptedKeyRepo) CreateKey(key *keys.Key) (*keys.Key, error) {
	encKey := &keys.Key{}
	if err := EncryptFields(encKey, key, r.KeyManager); err != nil {
		return nil, err
	}
	stored, err := r.KeyRepo.CreateKey(encKey)
	if err != nil {
		return nil, err
	}
	retKey := &keys.Key{}
	if err := DecryptFields(retKey, stored, r.KeyManager); err != nil {
		return nil, err
	}
	return retKey, nil
}

func (r *EncryptedKeyRepo) GetKey(id int, keyReference string, version int) (*keys.Key, error) {
	key, err := r.KeyRepo.GetKey(id, keyReference, version)
	if err != nil {
		return nil, err
	}

	retKey := &keys.Key{}
	if err := DecryptFields(retKey, key, r.KeyManager); err != nil {
		return nil, err
	}

	return retKey, nil
}

func (r *EncryptedKeyRepo) GetLatestKey(id int, keyReference string) (*keys.Key, error) {
	key, err := r.KeyRepo.GetLatestKey(id, keyReference)
	if err != nil {
		return nil, err
	}

	retKey := &keys.Key{}
	if err := DecryptFields(retKey, key, r.KeyManager); err != nil {
		return nil, err
	}

	return retKey, nil
}

func (r *EncryptedKeyRepo) UpdateKey(clientId int, keyReference string, version int, state string) error {
	encState, err := EncryptString(state, r.KeyManager.DBKey())
	if err != nil {
		return err
	}

	return r.KeyRepo.UpdateKey(clientId, keyReference, version, encState)
}

func (r *EncryptedKeyRepo) Delete(clientId int, keyReference string) (int, error) {
	return r.KeyRepo.Delete(clientId, keyReference)
}

// Dev
func (r *EncryptedKeyRepo) GetAll() ([]keys.Key, error) {
	return r.KeyRepo.GetAll()
}
