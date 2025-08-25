package encryption

import (
	"errors"
	"kms/internal/keys"
	"kms/internal/test"
	"kms/internal/test/mocks"
	"kms/pkg/encryption"
	"testing"
)

func TestCreateKey_Success(t *testing.T) {
	key := &keys.Key{
		ID:           1,
		ClientId:     1,
		KeyReference: "keyReference",
		Version:      1,
		DEK:          "validB64",
		State:        "state",
		Encoding:     "encoding",
	}
	mockRepo := keys.NewKeyRepositoryMock()
	mockRepo.CreateKeyFunc = func(k *keys.Key) (*keys.Key, error) {
		return k, nil
	}
	keyManager := mocks.NewKeyManagerMock()
	dbKey, err := encryption.GenerateKey(32)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	kek, err := encryption.GenerateKey(32)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	keyManager.DBKeyFunc = func() []byte {
		return dbKey
	}
	keyManager.KEKFunc = func() []byte {
		return kek
	}

	repo := NewEncryptedKeyRepo(mockRepo, keyManager)

	created, err := repo.CreateKey(key)

	test.RequireErrNil(t, err)

	if *created != *key {
		t.Errorf("original and created should be equal, got %v", created)
	}
}

func TestCreateKey_RepoError(t *testing.T) {
	key := &keys.Key{
		ID:           1,
		ClientId:     1,
		KeyReference: "keyReference",
		Version:      1,
		DEK:          "validB64",
		State:        "state",
		Encoding:     "encoding",
	}
	mockRepo := keys.NewKeyRepositoryMock()
	mockRepo.CreateKeyFunc = func(k *keys.Key) (*keys.Key, error) {
		return nil, errors.New("repo error")
	}
	keyManager := mocks.NewKeyManagerMock()
	dbKey, err := encryption.GenerateKey(32)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	kek, err := encryption.GenerateKey(32)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	keyManager.DBKeyFunc = func() []byte {
		return dbKey
	}
	keyManager.KEKFunc = func() []byte {
		return kek
	}

	repo := NewEncryptedKeyRepo(mockRepo, keyManager)

	_, err = repo.CreateKey(key)

	test.RequireErrNotNil(t, err)
	test.RequireErrContains(t, err, "repo error")
}

func TestGetKey_Success(t *testing.T) {
	keyManager := mocks.NewKeyManagerMock()
	dbKey, err := encryption.GenerateKey(32)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	kek, err := encryption.GenerateKey(32)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	keyManager.DBKeyFunc = func() []byte {
		return dbKey
	}
	keyManager.KEKFunc = func() []byte {
		return kek
	}

	key := &keys.Key{
		ID:           1,
		ClientId:     1,
		KeyReference: "keyReference",
		Version:      1,
		DEK:          "validB64",
		State:        "state",
		Encoding:     "encoding",
	}
	var enc keys.Key
	err = EncryptFields(&enc, key, keyManager)
	test.RequireErrNil(t, err)

	mockRepo := keys.NewKeyRepositoryMock()
	mockRepo.GetKeyFunc = func(id int, keyReference string, v int) (*keys.Key, error) {
		return &enc, nil
	}

	repo := NewEncryptedKeyRepo(mockRepo, keyManager)
	retrieved, err := repo.GetKey(1, "ref", 1)

	test.RequireErrNil(t, err)

	if *retrieved != *key {
		t.Errorf("expected original and retrieved to be same, got %v", retrieved)
	}
}

func TestGetKey_RepoError(t *testing.T) {
	mockRepo := keys.NewKeyRepositoryMock()
	mockRepo.GetKeyFunc = func(id int, ref string, v int) (*keys.Key, error) {
		return nil, errors.New("repo error")
	}
	keyManager := mocks.NewKeyManagerMock()
	repo := NewEncryptedKeyRepo(mockRepo, keyManager)

	_, err := repo.GetKey(1, "ref", 1)

	test.RequireErrNotNil(t, err)
	test.RequireErrContains(t, err, "repo error")
}

func TestGetLatestKey_Success(t *testing.T) {
	keyManager := mocks.NewKeyManagerMock()
	dbKey, err := encryption.GenerateKey(32)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	kek, err := encryption.GenerateKey(32)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	keyManager.DBKeyFunc = func() []byte {
		return dbKey
	}
	keyManager.KEKFunc = func() []byte {
		return kek
	}

	key := &keys.Key{
		ID:           1,
		ClientId:     1,
		KeyReference: "keyReference",
		Version:      1,
		DEK:          "validB64",
		State:        "state",
		Encoding:     "encoding",
	}
	var enc keys.Key
	err = EncryptFields(&enc, key, keyManager)
	test.RequireErrNil(t, err)

	mockRepo := keys.NewKeyRepositoryMock()
	mockRepo.GetLatestKeyFunc = func(id int, keyReference string) (*keys.Key, error) {
		return &enc, nil
	}

	repo := NewEncryptedKeyRepo(mockRepo, keyManager)
	retrieved, err := repo.GetLatestKey(1, "ref")

	test.RequireErrNil(t, err)

	if *retrieved != *key {
		t.Errorf("expected original and retrieved to be same, got %v", retrieved)
	}
}

func TestGetLatestKey_RepoError(t *testing.T) {
	mockRepo := keys.NewKeyRepositoryMock()
	mockRepo.GetKeyFunc = func(id int, ref string, v int) (*keys.Key, error) {
		return nil, errors.New("repo error")
	}
	keyManager := mocks.NewKeyManagerMock()
	repo := NewEncryptedKeyRepo(mockRepo, keyManager)

	_, err := repo.GetKey(1, "ref", 1)

	test.RequireErrNotNil(t, err)
	test.RequireErrContains(t, err, "repo error")
}

func TestUpdateKey_Success(t *testing.T) {
	keyManager := mocks.NewKeyManagerMock()
	dbKey, err := encryption.GenerateKey(32)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	kek, err := encryption.GenerateKey(32)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	keyManager.DBKeyFunc = func() []byte {
		return dbKey
	}
	keyManager.KEKFunc = func() []byte {
		return kek
	}

	key := &keys.Key{
		ID:           1,
		ClientId:     1,
		KeyReference: "keyReference",
		Version:      1,
		DEK:          "validB64",
		State:        "state",
		Encoding:     "encoding",
	}
	var enc keys.Key
	err = EncryptFields(&enc, key, keyManager)
	test.RequireErrNil(t, err)

	mockRepo := keys.NewKeyRepositoryMock()
	mockRepo.UpdateKeyFunc = func(id int, keyReference string, v int, s string) error {
		return nil
	}

	repo := NewEncryptedKeyRepo(mockRepo, keyManager)
	err = repo.UpdateKey(1, "ref", 1, "state")

	test.RequireErrNil(t, err)
}

func TestUpdateKey_InvalidKey(t *testing.T) {
	keyManager := mocks.NewKeyManagerMock()
	kek, err := encryption.GenerateKey(32)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	keyManager.KEKFunc = func() []byte {
		return kek
	}

	mockRepo := keys.NewKeyRepositoryMock()

	repo := NewEncryptedKeyRepo(mockRepo, keyManager)
	err = repo.UpdateKey(1, "ref", 1, "state")

	test.RequireErrNotNil(t, err)
}

func TestUpdateKey_RepoError(t *testing.T) {
	keyManager := mocks.NewKeyManagerMock()
	dbKey, err := encryption.GenerateKey(32)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	keyManager.DBKeyFunc = func() []byte {
		return dbKey
	}

	mockRepo := keys.NewKeyRepositoryMock()
	mockRepo.UpdateKeyFunc = func(x int, y string, v int, z string) error {
		return errors.New("repo error")
	}

	repo := NewEncryptedKeyRepo(mockRepo, keyManager)
	err = repo.UpdateKey(1, "ref", 1, "state")

	test.RequireErrNotNil(t, err)
	test.RequireContains(t, err.Error(), "repo error")
}

func TestDeleteKey_Success(t *testing.T) {
	mockRepo := keys.NewKeyRepositoryMock()
	mockRepo.DeleteFunc = func(x int, y string) (int, error) {
		return 1, nil
	}
	mockKeyManager := mocks.NewKeyManagerMock()

	repo := NewEncryptedKeyRepo(mockRepo, mockKeyManager)
	keyId, err := repo.Delete(12, "keyRef")

	test.RequireErrNil(t, err)
	if keyId != 1 {
		t.Errorf("expected keyId=1, got %d", keyId)
	}
}

func TestDeleteKey_RepoError(t *testing.T) {
	mockRepo := keys.NewKeyRepositoryMock()
	mockRepo.DeleteFunc = func(x int, y string) (int, error) {
		return 1, errors.New("repo error")
	}
	mockKeyManager := mocks.NewKeyManagerMock()

	repo := NewEncryptedKeyRepo(mockRepo, mockKeyManager)
	_, err := repo.Delete(12, "keyRef")

	test.RequireErrNotNil(t, err)
}

func TestGetAllKeys(t *testing.T) {
	keyManager := mocks.NewKeyManagerMock()
	stored := []keys.Key{
		{ID: 1, KeyReference: "reference"},
	}
	mockRepo := keys.NewKeyRepositoryMock()
	mockRepo.GetAllFunc = func() ([]keys.Key, error) {
		return stored, nil
	}
	repo := NewEncryptedKeyRepo(mockRepo, keyManager)

	retrieved, err := repo.GetAll()
	test.RequireErrNil(t, err)

	if len(retrieved) != 1 {
		t.Fatalf("expected retrieved to be size 1, got %v", len(retrieved))
	}

	if retrieved[0].ID != 1 || retrieved[0].KeyReference != "reference" {
		t.Errorf("expected ID=1 and reference='reference', got %v", retrieved[0])
	}
}
