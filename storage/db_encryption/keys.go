package db_encryption

import (
	"kms/storage"
)

type EncryptedKeyRepo struct {
	KeyRepo 	storage.KeyRepository 
	KEK 		[]byte
}

func NewEncryptedKeyRepo(keyRepo storage.KeyRepository, kek []byte) *EncryptedKeyRepo {
	return &EncryptedKeyRepo{
		KeyRepo: keyRepo,
		KEK: kek,
	}
}

func (r *EncryptedKeyRepo) CreateKey(key *storage.Key) (*storage.Key, error) {
	encKey := &storage.Key{}
	if err := EncryptFields(encKey, key, r.KEK); err != nil {
		return nil, err
	}
	stored, err := r.KeyRepo.CreateKey(encKey)
	if err != nil {
		return nil, err
	}
	retKey := &storage.Key{}
	if err := DecryptFields(retKey, stored, r.KEK); err != nil {
		return nil, err
	}
	return retKey, nil
}

func (r *EncryptedKeyRepo) GetKey(id int, keyReference string) (*storage.Key, error) {
	key, err := r.KeyRepo.GetKey(id, keyReference) 
	if err != nil {
		return nil, err
	}

	retKey := &storage.Key{}
	if err := DecryptFields(retKey, key, r.KEK); err != nil {
		return nil, err
	}

	return retKey, nil
}

// Dev
func (r *EncryptedKeyRepo) GetAll() ([]storage.Key, error) {
	return r.KeyRepo.GetAll()
}
