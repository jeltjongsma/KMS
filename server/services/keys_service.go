package services

import (
	"kms/storage"
	"kms/utils/kmsErrors"
	"kms/utils/encryption"
	"fmt"
	b64 "encoding/base64"
	"unicode"
)

type KeyService struct {
	KeyRepo storage.KeyRepository
	KEK 	[]byte
}

func NewKeyService(keyRepo storage.KeyRepository) *KeyService {
	return &KeyService{KeyRepo: keyRepo}
}

func (s *KeyService) CreateKey(userId int, keyReference string) (*storage.Key, *kmsErrors.AppError) {
	if err := validateKeyReference(keyReference); err != nil {
		return nil, kmsErrors.NewAppError(err, "Invalid key reference", 400)
	}

	DEKBytes, err := encryption.GenerateKey(32)
	if err != nil {
		return nil, kmsErrors.NewAppError(err, "Failed to generate key", 500)
	}

	// encryptedDEKBytes, err := encryption.Encrypt(DEKBytes, s.KEK)
	// if err != nil {
	// 	return storage.Key{}, kmsErrors.NewAppError(err)
	// }

	DEKB64 := b64.RawURLEncoding.EncodeToString(DEKBytes)

	key := &storage.Key{
		KeyReference: keyReference,
		// DEK: b64.RawURLEncoding.EncodeToString(encryptedDEKBytes),
		DEK: DEKB64,
		UserId: userId,
		Encoding: "base64url (RFC 4648)",
	}
	newKey, err := s.KeyRepo.CreateKey(key)
	if err != nil {
		return nil, kmsErrors.MapRepoErr(err)
	}

	return newKey, nil
}

// Allow 0-9, a-Z and '-' in custom key reference
func validateKeyReference(keyReference string) error {
	for _, r := range keyReference {
		if !(unicode.IsLetter(r) || unicode.IsDigit(r) || r == '-') {
			return fmt.Errorf("Invalid character in keyreference (%v): %v\n", keyReference, r)
		}
	}
	return nil
}

func (s *KeyService) GetKey(userId int, keyReference string) (*storage.Key, *kmsErrors.AppError) {
	key, err := s.KeyRepo.GetKey(userId, keyReference)
	if err != nil {
		return nil, kmsErrors.MapRepoErr(err)
	}
	return key, nil
}