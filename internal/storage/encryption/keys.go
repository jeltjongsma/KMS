package encryption

import (
	"kms/internal/keys"
)

type EncryptedKeyRepo struct {
	KeyRepo 	keys.KeyRepository 
	KEK 		[]byte
}

func NewEncryptedKeyRepo(keyRepo keys.KeyRepository, kek []byte) *EncryptedKeyRepo {
	return &EncryptedKeyRepo{
		KeyRepo: keyRepo,
		KEK: kek,
	}
}

func (r *EncryptedKeyRepo) CreateKey(key *keys.Key) (*keys.Key, error) {
	encKey := &keys.Key{}
	if err := EncryptFields(encKey, key, r.KEK); err != nil {
		return nil, err
	}
	stored, err := r.KeyRepo.CreateKey(encKey)
	if err != nil {
		return nil, err
	}
	retKey := &keys.Key{}
	if err := DecryptFields(retKey, stored, r.KEK); err != nil {
		return nil, err
	}
	return retKey, nil
}

func (r *EncryptedKeyRepo) GetKey(id int, keyReference string) (*keys.Key, error) {
	key, err := r.KeyRepo.GetKey(id, keyReference) 
	if err != nil {
		return nil, err
	}

	retKey := &keys.Key{}
	if err := DecryptFields(retKey, key, r.KEK); err != nil {
		return nil, err
	}

	return retKey, nil
}

// Dev
func (r *EncryptedKeyRepo) GetAll() ([]keys.Key, error) {
	return r.KeyRepo.GetAll()
}
