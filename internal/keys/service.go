package keys

import (
	"fmt"
	b64 "encoding/base64"
	"unicode"
	kmsErrors "kms/pkg/errors"
	"kms/pkg/encryption"
	"kms/pkg/hashing"
	c "kms/internal/bootstrap/context"
)

type Service struct {
	KeyRepo 		KeyRepository
	KeyManager 		c.KeyManager
	Logger 			c.Logger
}

func NewService(keyRepo KeyRepository, keyManager c.KeyManager, logger c.Logger) *Service {
	return &Service{
		KeyRepo: keyRepo,
		KeyManager: keyManager,
		Logger: logger,
	}
}

type KeyRepository interface {
	CreateKey(key *Key) (*Key, error)
	GetKey(id int, keyReference string) (*Key, error)
	GetAll() ([]Key, error)
}

func (s *Service) CreateKey(userId int, keyReference string) (*Key, *kmsErrors.AppError) {
	if err := validateKeyReference(keyReference); err != nil {
		return nil, kmsErrors.NewAppError(err, "Invalid key reference", 400)
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

func (s *Service) GetKey(userId int, keyReference string) (*Key, *kmsErrors.AppError) {
	keyRefSecret, err := s.KeyManager.HashKey("keyReference")
	if err != nil {
		return nil, kmsErrors.NewInternalServerError(err)
	}

	hashedReference := hashing.HashHS256ToB64([]byte(keyReference), keyRefSecret)
	key, err := s.KeyRepo.GetKey(userId, hashedReference)
	if err != nil {
		return nil, kmsErrors.MapRepoErr(err)
	}
	return key, nil
}

func (s *Service) GetAll() ([]Key, *kmsErrors.AppError) {
	keys, err := s.KeyRepo.GetAll()
	if err != nil {
		return nil, kmsErrors.MapRepoErr(err)
	}
	return keys, nil
}