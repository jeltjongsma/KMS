package encryption

import (
	"errors"
	"kms/internal/admin"
	"kms/internal/test/mocks"
	"kms/internal/users"
	"kms/pkg/encryption"
	"strings"
	"testing"
)

func TestGetAdmin_Success(t *testing.T) {
	dbKey, err := encryption.GenerateKey(32)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	keyManager := mocks.NewKeyManagerMock()
	keyManager.DBKeyFunc = func() []byte {
		return dbKey
	}

	original := &users.User{
		ID:             1,
		Username:       "username",
		HashedUsername: "hashedUsername",
		Password:       "password",
		Role:           "role",
	}
	var a users.User
	err = EncryptFields(&a, original, keyManager)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	mockRepo := admin.NewAdminRepositoryMock()
	mockRepo.GetAdminFunc = func(id int) (*users.User, error) {
		return &a, nil
	}

	repo := NewEncryptedAdminRepo(mockRepo, keyManager)
	retrieved, err := repo.GetAdmin(1)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if *retrieved != *original {
		t.Errorf("expected %v, got %v", original, retrieved)
	}
}

func TestAdmin_RepoError(t *testing.T) {
	mockRepo := admin.NewAdminRepositoryMock()
	mockRepo.GetAdminFunc = func(id int) (*users.User, error) {
		return nil, errors.New("repo error")
	}

	keyManager := mocks.NewKeyManagerMock()
	repo := NewEncryptedAdminRepo(mockRepo, keyManager)

	_, err := repo.GetAdmin(1)
	if err == nil {
		t.Fatalf("expected error")
	}
	if !strings.Contains(err.Error(), "repo error") {
		t.Errorf("expected repo error, got: %v", err.Error())
	}
}
