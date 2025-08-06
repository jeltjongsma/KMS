package keys

import (
	b64 "encoding/base64"
	"fmt"
	c "kms/internal/bootstrap/context"
	"kms/pkg/encryption"
	kmsErrors "kms/pkg/errors"
	"kms/pkg/hashing"
	"unicode"
)

type Service struct {
	KeyRepo    KeyRepository
	KeyManager c.KeyManager
	Logger     c.Logger
}

func NewService(keyRepo KeyRepository, keyManager c.KeyManager, logger c.Logger) *Service {
	return &Service{
		KeyRepo:    keyRepo,
		KeyManager: keyManager,
		Logger:     logger,
	}
}

type KeyRepository interface {
	CreateKey(key *Key) (*Key, error)
	GetKey(id int, keyReference string) (*Key, error)
	UpdateKey(id int, keyReference string, newKey string) (*Key, error)
	GetAll() ([]Key, error)
}

func (s *Service) CreateKey(userId int, keyReference string) (*Key, *kmsErrors.AppError) {
	if err := validateKeyReference(keyReference); err != nil {
		return nil, kmsErrors.NewAppError(err, "Key reference does not meet minimum requirements. 0 < len <= 64 & contains only [0-9a-Z\\-]", 400)
	}

	DEKBytes, err := encryption.GenerateKey(32)
	if err != nil {
		return nil, kmsErrors.NewAppError(err, "Failed to generate key", 500)
	}

	keyRefSecret, err := s.KeyManager.HashKey("keyReference")
	if err != nil {
		return nil, kmsErrors.NewInternalServerError(err)
	}

	// No need to check for collisions, since 'keyReference' column has unique constraint
	hashedReference := hashing.HashHS256ToB64([]byte(keyReference), keyRefSecret)
	DEKB64 := b64.RawURLEncoding.EncodeToString(DEKBytes)

	key := &Key{
		KeyReference: hashedReference,
		DEK:          DEKB64,
		UserId:       userId,
		Encoding:     "base64url (RFC 4648)",
	}
	newKey, err := s.KeyRepo.CreateKey(key)
	if err != nil {
		return nil, kmsErrors.MapRepoErr(err)
	}

	s.Logger.Info("Key created", "keyId", newKey.ID, "userId", newKey.UserId)

	return newKey, nil
}

// Allow 0-9, a-Z and '-' in custom key reference
func validateKeyReference(keyReference string) error {
	if len(keyReference) < 1 || len(keyReference) > 64 {
		return fmt.Errorf("key reference must be between 1 and 64 characters long, is %d", len(keyReference))
	}
	for _, r := range keyReference {
		if !(unicode.IsLetter(r) || unicode.IsDigit(r) || r == '-') {
			return fmt.Errorf("invalid character in keyreference (%v): %v", keyReference, r)
		}
	}
	return nil
}

func (s *Service) GetKey(userId int, keyReference string) (*Key, *kmsErrors.AppError) {
	if err := validateKeyReference(keyReference); err != nil {
		return nil, kmsErrors.NewAppError(err, "Invalid key reference", 400)
	}
	keyRefSecret, err := s.KeyManager.HashKey("keyReference")
	if err != nil {
		return nil, kmsErrors.NewInternalServerError(err)
	}

	hashedReference := hashing.HashHS256ToB64([]byte(keyReference), keyRefSecret)
	key, err := s.KeyRepo.GetKey(userId, hashedReference)
	if err != nil {
		return nil, kmsErrors.MapRepoErr(err)
	}

	s.Logger.Info("Key retrieved", "keyId", key.ID, "userId", userId)

	return key, nil
}

func (s *Service) RenewKey(userId int, keyReference string) (*Key, *kmsErrors.AppError) {
	if err := validateKeyReference(keyReference); err != nil {
		return nil, kmsErrors.NewAppError(err, "Invalid key reference", 400)
	}
	DEKBytes, err := encryption.GenerateKey(32)
	if err != nil {
		return nil, kmsErrors.NewInternalServerError(err)
	}

	DEKB64 := b64.RawURLEncoding.EncodeToString(DEKBytes)

	keyRefSecret, err := s.KeyManager.HashKey("keyReference")
	if err != nil {
		return nil, kmsErrors.NewInternalServerError(err)
	}

	hashedReference := hashing.HashHS256ToB64([]byte(keyReference), keyRefSecret)
	key, err := s.KeyRepo.UpdateKey(userId, hashedReference, DEKB64)
	if err != nil {
		return nil, kmsErrors.MapRepoErr(err)
	}

	s.Logger.Info("Key updated", "keyId", key.ID, "userId", userId)

	return key, nil
}

func (s *Service) GetAll() ([]Key, *kmsErrors.AppError) {
	keys, err := s.KeyRepo.GetAll()
	if err != nil {
		return nil, kmsErrors.MapRepoErr(err)
	}
	return keys, nil
}
