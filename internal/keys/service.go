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
	// For transaction support
	BeginTransaction() (KeyRepository, error)
	CommitTransaction() error
	RollbackTransaction() error

	CreateKey(key *Key) (*Key, error)
	GetKey(clientId int, keyReference string, version int) (*Key, error)
	GetLatestKey(clientId int, keyReference string) (*Key, error)
	UpdateKey(clientId int, keyReference string, version int, state string) error
	Delete(clientId int, keyReference string) (int, error)
	GetAll() ([]Key, error)
}

func (s *Service) CreateKey(clientId int, keyReference string, version int) (*Key, *kmsErrors.AppError) {
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

	// No need to check for collisions, since 'clientId', 'keyReference' and 'version' columns have unique constraint
	hashedReference := hashing.HashHS256ToB64([]byte(keyReference), keyRefSecret)
	DEKB64 := b64.RawURLEncoding.EncodeToString(DEKBytes)

	key := &Key{
		ClientId:     clientId,
		KeyReference: hashedReference,
		Version:      version,
		DEK:          DEKB64,
		State:        StateInUse,
		Encoding:     "base64url (RFC 4648)",
	}

	newKey, err := s.KeyRepo.CreateKey(key)
	if err != nil {
		return nil, kmsErrors.MapRepoErr(err)
	}

	s.Logger.Info("Key created", "keyId", newKey.ID, "clientId", newKey.ClientId)

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

func (s *Service) GetKey(clientId int, keyReference string, version int) (*Key, *Key, *kmsErrors.AppError) {
	if err := validateKeyReference(keyReference); err != nil {
		return nil, nil, kmsErrors.NewAppError(err, "Invalid key reference", 400)
	}
	keyRefSecret, err := s.KeyManager.HashKey("keyReference")
	if err != nil {
		return nil, nil, kmsErrors.NewInternalServerError(err)
	}

	hashedReference := hashing.HashHS256ToB64([]byte(keyReference), keyRefSecret)

	// get requested key
	decKey, err := s.KeyRepo.GetKey(clientId, hashedReference, version)
	if err != nil {
		return nil, nil, kmsErrors.MapRepoErr(err)
	}

	s.Logger.Info("Key retrieved", "keyId", decKey.ID, "clientId", clientId)

	// get latest key
	encKey, err := s.KeyRepo.GetLatestKey(clientId, hashedReference)
	if err != nil {
		return nil, nil, kmsErrors.MapRepoErr(err)
	}

	s.Logger.Info("Key retrieved", "keyId", encKey.ID, "clientId", clientId)

	return decKey, encKey, nil
}

func (s *Service) RotateKey(clientId int, keyReference string) (key *Key, appErr *kmsErrors.AppError) {
	if err := validateKeyReference(keyReference); err != nil {
		return nil, kmsErrors.NewAppError(err, "Invalid key reference", 400)
	}

	keyRefSecret, err := s.KeyManager.HashKey("keyReference")
	if err != nil {
		return nil, kmsErrors.NewInternalServerError(err)
	}

	hashedReference := hashing.HashHS256ToB64([]byte(keyReference), keyRefSecret)

	// begin transaction
	newRepo, err := s.KeyRepo.BeginTransaction()
	if err != nil {
		return nil, kmsErrors.MapRepoErr(err)
	}
	s.KeyRepo = newRepo

	// ensure rollback if anything fails
	defer func() {
		err := s.KeyRepo.RollbackTransaction()
		s.Logger.Debug("Transaction rollback attempted", "error", err)

		if err != nil {
			// log the rollback error, but return the original error (if any)
			s.Logger.Critical("Failed to rollback transaction", "error", err.Error(), "clientId", clientId, "keyReference", keyReference)
			if appErr == nil {
				appErr = kmsErrors.MapRepoErr(err)
			}
		}
	}()

	s.Logger.Info("Key rotation started", "clientId", clientId)

	// get latest key
	latest, err := s.KeyRepo.GetLatestKey(clientId, hashedReference)
	if err != nil {
		return nil, kmsErrors.MapRepoErr(err)
	}

	s.Logger.Info("Latest key retrieved", "keyId", latest.ID, "clientId", clientId)

	// set latest key's state to deprecated
	if err := s.KeyRepo.UpdateKey(clientId, hashedReference, latest.Version, StateDeprecated); err != nil {
		return nil, kmsErrors.MapRepoErr(err)
	}

	s.Logger.Info("Latest key deprecated", "keyId", latest.ID, "clientId", clientId)

	// create new key
	newKey, appErr := s.CreateKey(clientId, keyReference, latest.Version+1)
	if appErr != nil {
		return nil, appErr // TODO: Wrap so it's clear which function threw an error
	}

	s.Logger.Info("New key created", "keyId", newKey.ID, "clientId", clientId)

	// commit transaction
	if err := s.KeyRepo.CommitTransaction(); err != nil {
		return nil, kmsErrors.MapRepoErr(err)
	}

	s.Logger.Info("Key rotated", "keyId", newKey.ID, "clientId", clientId)

	return newKey, nil
}

func (s *Service) DeleteKey(clientId int, keyReference string) *kmsErrors.AppError {
	if err := validateKeyReference(keyReference); err != nil {
		return kmsErrors.NewAppError(err, "Invalid key reference", 400)
	}

	keyRefSecret, err := s.KeyManager.HashKey("keyReference")
	if err != nil {
		return kmsErrors.NewInternalServerError(err)
	}

	hashedReference := hashing.HashHS256ToB64([]byte(keyReference), keyRefSecret)
	keyId, err := s.KeyRepo.Delete(clientId, hashedReference)
	if err != nil {
		return kmsErrors.MapRepoErr(err)
	}

	s.Logger.Info("Key deleted", "keyId", keyId, "clientId", clientId)

	return nil
}

func (s *Service) GetAll() ([]Key, *kmsErrors.AppError) {
	keys, err := s.KeyRepo.GetAll()
	if err != nil {
		return nil, kmsErrors.MapRepoErr(err)
	}
	return keys, nil
}
