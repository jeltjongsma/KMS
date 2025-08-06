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
		KeyReference: "keyReference",
		DEK:          "validB64",
		UserId:       1,
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
		KeyReference: "keyReference",
		DEK:          "validB64",
		UserId:       1,
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
		KeyReference: "keyReference",
		DEK:          "validB64",
		UserId:       1,
		Encoding:     "encoding",
	}
	var enc keys.Key
	err = EncryptFields(&enc, key, keyManager)
	test.RequireErrNil(t, err)

	mockRepo := keys.NewKeyRepositoryMock()
	mockRepo.GetKeyFunc = func(id int, keyReference string) (*keys.Key, error) {
		return &enc, nil
	}

	repo := NewEncryptedKeyRepo(mockRepo, keyManager)
	retrieved, err := repo.GetKey(1, "ref")

	test.RequireErrNil(t, err)

	if *retrieved != *key {
		t.Errorf("expected original and retrieved to be same, got %v", retrieved)
	}
}

func TestGetKey_RepoError(t *testing.T) {
	mockRepo := keys.NewKeyRepositoryMock()
	mockRepo.GetKeyFunc = func(id int, ref string) (*keys.Key, error) {
		return nil, errors.New("repo error")
	}
	keyManager := mocks.NewKeyManagerMock()
	repo := NewEncryptedKeyRepo(mockRepo, keyManager)

	_, err := repo.GetKey(1, "ref")

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
		KeyReference: "keyReference",
		DEK:          "validB64",
		UserId:       1,
		Encoding:     "encoding",
	}
	var enc keys.Key
	err = EncryptFields(&enc, key, keyManager)
	test.RequireErrNil(t, err)

	mockRepo := keys.NewKeyRepositoryMock()
	mockRepo.UpdateKeyFunc = func(id int, keyReference string, new string) (*keys.Key, error) {
		return &enc, nil
	}

	repo := NewEncryptedKeyRepo(mockRepo, keyManager)
	retrieved, err := repo.UpdateKey(1, "ref", "newValidB64")

	test.RequireErrNil(t, err)

	if *retrieved != *key {
		t.Errorf("expected original and retrieved to be different, got %v", retrieved)
	}
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
	_, err = repo.UpdateKey(1, "ref", "not+base64")

	test.RequireErrNotNil(t, err)
	test.RequireContains(t, err.Error(), "illegal base64 data")
}

func TestUpdateKey_RepoError(t *testing.T) {
	keyManager := mocks.NewKeyManagerMock()
	kek, err := encryption.GenerateKey(32)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	keyManager.KEKFunc = func() []byte {
		return kek
	}

	mockRepo := keys.NewKeyRepositoryMock()
	mockRepo.UpdateKeyFunc = func(x int, y, z string) (*keys.Key, error) {
		return nil, errors.New("repo error")
	}

	repo := NewEncryptedKeyRepo(mockRepo, keyManager)
	_, err = repo.UpdateKey(1, "ref", "validBase64")

	test.RequireErrNotNil(t, err)
	test.RequireContains(t, err.Error(), "repo error")
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
