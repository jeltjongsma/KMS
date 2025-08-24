package keys

import (
	"errors"
	"kms/internal/test"
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

	key, err := service.CreateKey(1, "testKey", 1)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	hashedReference := hashing.HashHS256ToB64([]byte("testKey"), keyRefSecret)
	if key == nil || key.KeyReference != hashedReference {
		t.Errorf("expected key with reference '%s', got %v", hashedReference, key)
	}
	if key.ClientId != 1 {
		t.Errorf("expected key clientId 1, got %d", key.ClientId)
	}
	if key.Version != 1 {
		t.Errorf("expected key version 1, got %d", key.Version)
	}
}

func TestService_CreateKey_ValidateReferenceError(t *testing.T) {
	mockRepo := NewKeyRepositoryMock()
	mockLogger := mocks.NewLoggerMock()
	mockKeyManager := mocks.NewKeyManagerMock()

	service := NewService(mockRepo, mockKeyManager, mockLogger)

	_, err := service.CreateKey(1, "invalid/key", 1)
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

	_, err := service.CreateKey(1, "testKey", 1)
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

	_, err := service.CreateKey(1, "testKey", 1)
	if err == nil || !strings.Contains(err.Err.Error(), "repo error") {
		t.Fatalf("expected repo error, got %v", err)
	}
	if err.Code != 500 {
		t.Errorf("expected error code 500, got %d", err.Code)
	}
}

func TestService_GetKey_Success(t *testing.T) {
	mockRepo := NewKeyRepositoryMock()
	mockRepo.GetKeyFunc = func(clientId int, keyReference string, version int) (*Key, error) {
		return &Key{ClientId: clientId, KeyReference: "testKey", Version: 1}, nil
	}
	mockRepo.GetLatestKeyFunc = func(clientId int, keyReference string) (*Key, error) {
		return &Key{ClientId: clientId, KeyReference: "testKey", Version: 2}, nil
	}
	mockLogger := mocks.NewLoggerMock()
	mockKeyManager := mocks.NewKeyManagerMock()
	mockKeyManager.HashKeyFunc = func(key string) ([]byte, error) {
		return []byte("keyRefSecret"), nil
	}

	service := NewService(mockRepo, mockKeyManager, mockLogger)

	decKey, encKey, err := service.GetKey(1, "testKey", 1)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if decKey == nil || decKey.KeyReference != "testKey" {
		t.Errorf("expected decryption key with reference 'testKey', got %v", decKey)
	}
	if decKey.ClientId != 1 {
		t.Errorf("expected decryption key clientId 1, got %d", decKey.ClientId)
	}
	if decKey.Version != 1 {
		t.Errorf("expected decryption key version 1, got %d", decKey.Version)
	}
	if encKey == nil || encKey.KeyReference != "testKey" {
		t.Errorf("expected encryption key with reference 'testKey', got %v", encKey)
	}
	if encKey.ClientId != 1 {
		t.Errorf("expected encryption key clientId 1, got %d", encKey.ClientId)
	}
	if encKey.Version != 2 {
		t.Errorf("expected encryption key version 1, got %d", encKey.Version)
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
	_, _, err := service.GetKey(1, "testKey", 1)
	if err == nil || err.Err.Error() != "hashing error" {
		t.Fatalf("expected hashing error, got %v", err)
	}
	if err.Code != 500 {
		t.Errorf("expected error code 500, got %d", err.Code)
	}
}

func TestService_GetKey_RepoError(t *testing.T) {
	mockRepo := NewKeyRepositoryMock()
	mockRepo.GetKeyFunc = func(id int, keyReference string, v int) (*Key, error) {
		return nil, errors.New("repo error")
	}
	mockLogger := mocks.NewLoggerMock()
	mockKeyManager := mocks.NewKeyManagerMock()
	service := NewService(mockRepo, mockKeyManager, mockLogger)
	_, _, err := service.GetKey(1, "testKey", 1)
	if err == nil || err.Err.Error() != "repo error" {
		t.Fatalf("expected repo error, got %v", err)
	}
	if err.Code != 500 {
		t.Errorf("expected error code 500, got %d", err.Code)
	}
}

func TestService_RotateKey_Success(t *testing.T) {
	clientId := 1
	mockRepo := NewKeyRepositoryMock()
	mockRepo.BeginTransactionFunc = func() (KeyRepository, error) { return mockRepo, nil }
	mockRepo.CommitTransactionFunc = func() error { return nil }
	mockRepo.RollbackTransactionFunc = func() error { return nil }
	mockRepo.GetLatestKeyFunc = func(c int, k string) (*Key, error) {
		return &Key{ClientId: clientId, KeyReference: "testKey", Version: 1}, nil
	}
	mockRepo.UpdateKeyFunc = func(clientId int, keyRef string, version int, state string) error {
		return nil
	}
	mockRepo.CreateKeyFunc = func(key *Key) (*Key, error) {
		return &Key{ClientId: clientId, KeyReference: "testKey", Version: 2}, nil
	}

	// capture critical logs for rollback failures
	logs := []string{}
	mockLogger := mocks.NewLoggerMock()
	mockLogger.CriticalFunc = func(msg string, keysAndValues ...any) {
		logs = append(logs, msg)
	}

	refKey := []byte("keyRefHashKey")
	mockKeyManager := mocks.NewKeyManagerMock()
	mockKeyManager.HashKeyFunc = func(ref string) ([]byte, error) {
		return refKey, nil
	}

	service := NewService(mockRepo, mockKeyManager, mockLogger)

	key, appErr := service.RotateKey(1, "keyRef")
	if appErr != nil {
		t.Fatalf("unexpected error: %v", appErr)
	}

	if key == nil {
		t.Fatal("expected key, got nil")
	}

	if key.ClientId != 1 {
		t.Errorf("expected key clientId = 1, got %d", key.ClientId)
	}
	if key.KeyReference != "testKey" {
		t.Errorf("expected key reference = 'testKey', got %s", key.KeyReference)
	}
	if key.Version != 2 {
		t.Errorf("expected key version = 2, got %d", key.Version)
	}

	if len(logs) != 0 {
		t.Errorf("expected no critical logs, got %v", logs)
	}
}

func TestService_RotateKey_MissingHashKey(t *testing.T) {
	mockRepo := NewKeyRepositoryMock()
	mockLogger := mocks.NewLoggerMock()
	mockKeyManager := mocks.NewKeyManagerMock()
	mockKeyManager.HashKeyFunc = func(ref string) ([]byte, error) {
		return nil, errors.New("keymanager error")
	}

	service := NewService(mockRepo, mockKeyManager, mockLogger)

	_, appErr := service.RotateKey(1, "keyRef")
	if appErr == nil {
		t.Fatal("expected key manager error")
	}

	if appErr.Code != 500 {
		t.Errorf("expected status 500, got %d", appErr.Code)
	}

	if appErr.Err.Error() != "keymanager error" {
		t.Errorf("expected keymanager error, got %v", appErr.Err)
	}
}

func TestService_RotateKey_RepoError(t *testing.T) {

	tests := []struct {
		getLatestFunc func(c int, r string) (*Key, error)
		updateFunc    func(c int, r string, v int, s string) error
	}{
		{
			func(c int, r string) (*Key, error) { return nil, errors.New("repo error") },
			func(c int, r string, v int, s string) error { return nil },
		},
		{
			func(c int, r string) (*Key, error) {
				return &Key{ClientId: 1, KeyReference: "testKey", Version: 1}, nil
			},
			func(c int, r string, v int, s string) error { return errors.New("repo error") },
		},
	}

	for _, tt := range tests {
		mockRepo := NewKeyRepositoryMock()
		mockRepo.BeginTransactionFunc = func() (KeyRepository, error) { return mockRepo, nil }
		mockRepo.CommitTransactionFunc = func() error { return nil }
		mockRepo.UpdateKeyFunc = tt.updateFunc
		mockRepo.GetLatestKeyFunc = tt.getLatestFunc

		// capture debug logs for rollback attempts
		logs := []string{}
		mockLogger := mocks.NewLoggerMock()
		mockLogger.DebugFunc = func(msg string, keysAndValues ...any) {
			logs = append(logs, msg)
		}

		refKey := []byte("keyRefHashKey")
		mockKeyManager := mocks.NewKeyManagerMock()
		mockKeyManager.HashKeyFunc = func(ref string) ([]byte, error) {
			return refKey, nil
		}

		service := NewService(mockRepo, mockKeyManager, mockLogger)

		_, appErr := service.RotateKey(1, "keyRef")
		if appErr == nil {
			t.Fatal("expected repo error")
		}

		if appErr.Code != 500 {
			t.Errorf("expected status 500, got %d", appErr.Code)
		}

		if appErr.Err.Error() != "repo error" {
			t.Errorf("expected repo error, got %v", appErr.Err)
		}

		if len(logs) == 0 {
			t.Errorf("expected debug log for rollback attempt, got none")
		}

		rollbackAttempted := false
		for _, logMsg := range logs {
			if strings.Contains(logMsg, "Transaction rollback attempted") {
				rollbackAttempted = true
			}
		}
		if !rollbackAttempted {
			t.Errorf("expected debug log for rollback attempt, got: %v", logs)
		}
	}
}

func TestService_RotateKey_ServiceError(t *testing.T) {
	clientId := 1
	mockRepo := NewKeyRepositoryMock()
	mockRepo.BeginTransactionFunc = func() (KeyRepository, error) { return mockRepo, nil }
	mockRepo.CommitTransactionFunc = func() error { return nil }
	mockRepo.GetLatestKeyFunc = func(c int, k string) (*Key, error) {
		return &Key{ClientId: clientId, KeyReference: "testKey", Version: 1}, nil
	}
	mockRepo.UpdateKeyFunc = func(clientId int, keyRef string, version int, state string) error {
		return nil
	}
	mockRepo.CreateKeyFunc = func(key *Key) (*Key, error) {
		return nil, errors.New("repo error")
	}

	// capture debug logs for rollback attempts
	logs := []string{}
	mockLogger := mocks.NewLoggerMock()
	mockLogger.DebugFunc = func(msg string, keysAndValues ...any) {
		logs = append(logs, msg)
	}

	refKey := []byte("keyRefHashKey")
	mockKeyManager := mocks.NewKeyManagerMock()
	mockKeyManager.HashKeyFunc = func(ref string) ([]byte, error) {
		return refKey, nil
	}

	service := NewService(mockRepo, mockKeyManager, mockLogger)

	key, appErr := service.RotateKey(1, "keyRef")

	if key != nil {
		t.Fatalf("expected key = nil, got %v", key)
	}
	if appErr == nil {
		t.Fatal("expected error, got nil")
	}
	if appErr.Err.Error() != "repo error" {
		t.Errorf("expected repo error")
	}
	if appErr.Code != 500 {
		t.Errorf("expected code 500, got %d", appErr.Code)
	}

	if len(logs) == 0 {
		t.Errorf("expected debug log for rollback attempt, got none")
	}

	rollbackAttempted := false
	for _, logMsg := range logs {
		if strings.Contains(logMsg, "Transaction rollback attempted") {
			rollbackAttempted = true
		}
	}
	if !rollbackAttempted {
		t.Errorf("expected debug log for rollback attempt, got: %v", logs)
	}
}

func TestService_RotateKey_BeginTransactionError(t *testing.T) {
	mockRepo := NewKeyRepositoryMock()
	mockRepo.BeginTransactionFunc = func() (KeyRepository, error) {
		return nil, errors.New("begin transaction error")
	}
	mockLogger := mocks.NewLoggerMock()
	mockKeyManager := mocks.NewKeyManagerMock()

	service := NewService(mockRepo, mockKeyManager, mockLogger)

	_, appErr := service.RotateKey(1, "keyRef")

	if appErr == nil || appErr.Err.Error() != "begin transaction error" {
		t.Fatalf("expected begin transaction error, got %v", appErr)
	}

	if appErr.Code != 500 {
		t.Errorf("expected error code 500, got %d", appErr.Code)
	}
}

func TestService_RotateKey_CommitTransactionError(t *testing.T) {
	clientId := 1
	mockRepo := NewKeyRepositoryMock()
	mockRepo.BeginTransactionFunc = func() (KeyRepository, error) { return mockRepo, nil }
	mockRepo.CommitTransactionFunc = func() error { return errors.New("commit transaction error") }
	mockRepo.RollbackTransactionFunc = func() error { return nil }
	mockRepo.GetLatestKeyFunc = func(c int, k string) (*Key, error) {
		return &Key{ClientId: clientId, KeyReference: "testKey", Version: 1}, nil
	}
	mockRepo.UpdateKeyFunc = func(clientId int, keyRef string, version int, state string) error {
		return nil
	}
	mockRepo.CreateKeyFunc = func(key *Key) (*Key, error) {
		return &Key{ClientId: clientId, KeyReference: "testKey", Version: 2}, nil
	}

	mockLogger := mocks.NewLoggerMock()

	refKey := []byte("keyRefHashKey")
	mockKeyManager := mocks.NewKeyManagerMock()
	mockKeyManager.HashKeyFunc = func(ref string) ([]byte, error) {
		return refKey, nil
	}

	service := NewService(mockRepo, mockKeyManager, mockLogger)

	key, appErr := service.RotateKey(1, "keyRef")

	if appErr == nil {
		t.Fatal("expected commit transaction error")
	}

	if key != nil {
		t.Errorf("expected key = nil, got %v", key)
	}

	if appErr.Code != 500 {
		t.Errorf("expected error code 500, got %d", appErr.Code)
	}

	if appErr.Err.Error() != "commit transaction error" {
		t.Errorf("expected commit transaction error, got %v", appErr.Err)
	}
}

func TestService_RotateKey_RollbackTransactionError(t *testing.T) {
	clientId := 1
	mockRepo := NewKeyRepositoryMock()
	mockRepo.BeginTransactionFunc = func() (KeyRepository, error) { return mockRepo, nil }
	mockRepo.CommitTransactionFunc = func() error { return nil }
	mockRepo.RollbackTransactionFunc = func() error { return errors.New("rollback transaction error") }
	mockRepo.GetLatestKeyFunc = func(c int, k string) (*Key, error) {
		return &Key{ClientId: clientId, KeyReference: "testKey", Version: 1}, nil
	}
	mockRepo.UpdateKeyFunc = func(clientId int, keyRef string, version int, state string) error {
		return nil
	}
	mockRepo.CreateKeyFunc = func(key *Key) (*Key, error) {
		return nil, errors.New("repo error")
	}

	// capture critical logs for rollback failures
	logs := []string{}
	mockLogger := mocks.NewLoggerMock()
	mockLogger.CriticalFunc = func(msg string, keysAndValues ...any) {
		logs = append(logs, msg)
	}

	refKey := []byte("keyRefHashKey")
	mockKeyManager := mocks.NewKeyManagerMock()
	mockKeyManager.HashKeyFunc = func(ref string) ([]byte, error) {
		return refKey, nil
	}

	service := NewService(mockRepo, mockKeyManager, mockLogger)

	key, appErr := service.RotateKey(1, "keyRef")

	if key != nil {
		t.Fatalf("expected key = nil, got %v", key)
	}
	if appErr == nil {
		t.Fatal("expected error, got nil")
	}
	if appErr.Err.Error() != "repo error" {
		t.Errorf("expected repo error")
	}
	if appErr.Code != 500 {
		t.Errorf("expected code 500, got %d", appErr.Code)
	}

	if len(logs) == 0 {
		t.Errorf("expected critical log for rollback failure, got none")
	}

	rollbackLogged := false
	for _, logMsg := range logs {
		if strings.Contains(logMsg, "Failed to rollback transaction") {
			rollbackLogged = true
		}
	}
	if !rollbackLogged {
		t.Errorf("expected critical log for rollback failure, got: %v", logs)
	}
}

func TestService_DeleteKey_Success(t *testing.T) {
	mockRepo := NewKeyRepositoryMock()
	mockRepo.DeleteFunc = func(clientId int, keyRef string) (int, error) {
		return 1, nil
	}
	mockLogger := mocks.NewLoggerMock()
	refKey := []byte("keyRefHashKey")
	mockKeyManager := mocks.NewKeyManagerMock()
	mockKeyManager.HashKeyFunc = func(ref string) ([]byte, error) {
		return refKey, nil
	}

	service := NewService(mockRepo, mockKeyManager, mockLogger)

	appErr := service.DeleteKey(1, "keyRef")
	if appErr != nil {
		t.Fatalf("unexpected error: %v", appErr)
	}
}

func TestService_DeleteKey_InvalidKeyReference(t *testing.T) {
	mockRepo := NewKeyRepositoryMock()
	mockLogger := mocks.NewLoggerMock()
	mockKeyManager := mocks.NewKeyManagerMock()

	service := NewService(mockRepo, mockKeyManager, mockLogger)

	appErr := service.DeleteKey(1, "invalid+keyRef")
	if appErr == nil {
		t.Fatal("expected error, got nil")
	}

	if appErr.Code != 400 {
		t.Errorf("expected status 400, got %d", appErr.Code)
	}
	if appErr.Message != "Invalid key reference" {
		t.Errorf("expected 'Invalid key reference', got %s", appErr.Message)
	}
}

func TestService_DeleteKey_MissingHashKey(t *testing.T) {
	mockRepo := NewKeyRepositoryMock()
	mockRepo.DeleteFunc = func(clientId int, keyRef string) (int, error) {
		return 1, nil
	}
	mockLogger := mocks.NewLoggerMock()
	mockKeyManager := mocks.NewKeyManagerMock()
	mockKeyManager.HashKeyFunc = func(ref string) ([]byte, error) {
		return nil, errors.New("keymanager error")
	}

	service := NewService(mockRepo, mockKeyManager, mockLogger)

	appErr := service.DeleteKey(1, "keyRef")

	if appErr == nil {
		t.Fatal("expected error, got nil")
	}
	test.RequireContains(t, appErr.Err.Error(), "keymanager error")
}

func TestService_DeleteKey_RepoError(t *testing.T) {
	mockRepo := NewKeyRepositoryMock()
	mockRepo.DeleteFunc = func(clientId int, keyRef string) (int, error) {
		return 1, errors.New("repo error")
	}
	mockLogger := mocks.NewLoggerMock()
	refKey := []byte("keyRefHashKey")
	mockKeyManager := mocks.NewKeyManagerMock()
	mockKeyManager.HashKeyFunc = func(ref string) ([]byte, error) {
		return refKey, nil
	}

	service := NewService(mockRepo, mockKeyManager, mockLogger)

	appErr := service.DeleteKey(1, "keyRef")

	if appErr == nil {
		t.Fatal("expected error, got nil")
	}
	test.RequireContains(t, appErr.Err.Error(), "repo error")
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
