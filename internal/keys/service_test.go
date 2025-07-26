package keys

import (
	"errors"
	"kms/internal/test/mocks"
	"kms/pkg/hashing"
	"strings"
	"testing"
)

func TestService_CreateKey_Success(t *testing.T) {
	mockRepo := NewKeyRepositoryMock()
	mockRepo.CreateKeyFunc = func(key *Key) (*Key, error) {
		return key, nil
	}
	mockLogger := mocks.NewLoggerMock()
	mockKeyManager := mocks.NewKeyManagerMock()
	keyRefSecret := []byte("keyRefSecret")
	mockKeyManager.HashKeyFunc = func(key string) ([]byte, error) {
		return keyRefSecret, nil
	}

	service := NewService(mockRepo, mockKeyManager, mockLogger)

	key, err := service.CreateKey(1, "testKey")
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	hashedReference := hashing.HashHS256ToB64([]byte("testKey"), keyRefSecret)
	if key == nil || key.KeyReference != hashedReference {
		t.Errorf("expected key with reference '%s', got %v", hashedReference, key)
	}
	if key.UserId != 1 {
		t.Errorf("expected key ID 1, got %d", key.ID)
	}
}

func TestService_CreateKey_ValidateReferenceError(t *testing.T) {
	mockRepo := NewKeyRepositoryMock()
	mockLogger := mocks.NewLoggerMock()
	mockKeyManager := mocks.NewKeyManagerMock()

	service := NewService(mockRepo, mockKeyManager, mockLogger)

	_, err := service.CreateKey(1, "invalid/key")
	if err == nil || !strings.Contains(err.Err.Error(), "invalid character in keyreference") {
		t.Fatalf("expected validation error, got %v", err)
	}
	if err.Code != 400 {
		t.Errorf("expected error code 400, got %d", err.Code)
	}
}

func TestService_CreateKey_HashKeyError(t *testing.T) {
	mockRepo := NewKeyRepositoryMock()
	mockLogger := mocks.NewLoggerMock()
	mockKeyManager := mocks.NewKeyManagerMock()
	mockKeyManager.HashKeyFunc = func(key string) ([]byte, error) {
		return nil, errors.New("hashing error")
	}

	service := NewService(mockRepo, mockKeyManager, mockLogger)

	_, err := service.CreateKey(1, "testKey")
	if err == nil || !strings.Contains(err.Err.Error(), "hashing error") {
		t.Fatalf("expected hashing error, got %v", err)
	}
	if err.Code != 500 {
		t.Errorf("expected error code 500, got %d", err.Code)
	}
}

func TestService_CreateKey_RepoError(t *testing.T) {
	mockRepo := NewKeyRepositoryMock()
	mockRepo.CreateKeyFunc = func(key *Key) (*Key, error) {
		return nil, errors.New("repo error")
	}
	mockLogger := mocks.NewLoggerMock()
	mockKeyManager := mocks.NewKeyManagerMock()
	mockKeyManager.HashKeyFunc = func(key string) ([]byte, error) {
		return []byte("keyRefSecret"), nil
	}

	service := NewService(mockRepo, mockKeyManager, mockLogger)

	_, err := service.CreateKey(1, "testKey")
	if err == nil || !strings.Contains(err.Err.Error(), "repo error") {
		t.Fatalf("expected repo error, got %v", err)
	}
	if err.Code != 500 {
		t.Errorf("expected error code 500, got %d", err.Code)
	}
}

func TestService_GetKey_Success(t *testing.T) {
	mockRepo := NewKeyRepositoryMock()
	mockRepo.GetKeyFunc = func(userId int, keyReference string) (*Key, error) {
		return &Key{ID: userId, KeyReference: "testKey"}, nil
	}
	mockLogger := mocks.NewLoggerMock()
	mockKeyManager := mocks.NewKeyManagerMock()
	mockKeyManager.HashKeyFunc = func(key string) ([]byte, error) {
		return []byte("keyRefSecret"), nil
	}

	service := NewService(mockRepo, mockKeyManager, mockLogger)

	key, err := service.GetKey(1, "testKey")
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if key == nil || key.KeyReference != "testKey" {
		t.Errorf("expected key with reference 'testKey', got %v", key)
	}
	if key.ID != 1 {
		t.Errorf("expected key ID 1, got %d", key.ID)
	}
}

func TestService_GetKey_KeyManagerError(t *testing.T) {
	mockRepo := NewKeyRepositoryMock()
	mockLogger := mocks.NewLoggerMock()
	mockKeyManager := mocks.NewKeyManagerMock()
	mockKeyManager.HashKeyFunc = func(key string) ([]byte, error) {
		return nil, errors.New("hashing error")
	}
	service := NewService(mockRepo, mockKeyManager, mockLogger)
	_, err := service.GetKey(1, "testKey")
	if err == nil || err.Err.Error() != "hashing error" {
		t.Fatalf("expected hashing error, got %v", err)
	}
	if err.Code != 500 {
		t.Errorf("expected error code 500, got %d", err.Code)
	}
}

func TestService_GetKey_RepoError(t *testing.T) {
	mockRepo := NewKeyRepositoryMock()
	mockRepo.GetKeyFunc = func(id int, keyReference string) (*Key, error) {
		return nil, errors.New("repo error")
	}
	mockLogger := mocks.NewLoggerMock()
	mockKeyManager := mocks.NewKeyManagerMock()
	service := NewService(mockRepo, mockKeyManager, mockLogger)
	_, err := service.GetKey(1, "testKey")
	if err == nil || err.Err.Error() != "repo error" {
		t.Fatalf("expected repo error, got %v", err)
	}
	if err.Code != 500 {
		t.Errorf("expected error code 500, got %d", err.Code)
	}
}

func TestService_GetAll_Success(t *testing.T) {
	mockRepo := NewKeyRepositoryMock()
	mockRepo.GetAllFunc = func() ([]Key, error) {
		return []Key{{ID: 1, KeyReference: "testKey"}}, nil
	}
	mockLogger := mocks.NewLoggerMock()
	mockKeyManager := mocks.NewKeyManagerMock()

	service := NewService(mockRepo, mockKeyManager, mockLogger)

	keys, err := service.GetAll()
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if len(keys) != 1 || keys[0].KeyReference != "testKey" {
		t.Errorf("expected one key with reference 'testKey', got %v", keys)
	}
}

func TestService_GetAll_RepoError(t *testing.T) {
	mockRepo := NewKeyRepositoryMock()
	mockRepo.GetAllFunc = func() ([]Key, error) {
		return nil, errors.New("repo error")
	}
	mockLogger := mocks.NewLoggerMock()
	mockKeyManager := mocks.NewKeyManagerMock()

	service := NewService(mockRepo, mockKeyManager, mockLogger)

	_, err := service.GetAll()
	if err == nil || !strings.Contains(err.Err.Error(), "repo error") {
		t.Fatalf("expected repo error, got %v", err)
	}
	if err.Code != 500 {
		t.Errorf("expected error code 500, got %d", err.Code)
	}
}

func TestService_validateKeyReference(t *testing.T) {
	tests := []struct {
		keyReference string
		expectError  bool
	}{
		{"valid-key123", false},
		{"invalid/key", true},
		{"another_invalid_key!", true},
		{"", true},
		{"a", false},
		{"valid-key-with-maximum-length-12345678901234567890123456789012345678901234567890123456789012345678901234567890", true},
	}
	for _, tt := range tests {
		err := validateKeyReference(tt.keyReference)
		if (err != nil) != tt.expectError {
			t.Errorf("validateKeyReference(%q) error = %v, expectError %v", tt.keyReference, err, tt.expectError)
			continue
		}
	}
}
