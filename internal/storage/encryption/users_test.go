package encryption

import (
	"errors"
	"kms/internal/clients"
	"kms/internal/test"
	"kms/internal/test/mocks"
	"kms/pkg/encryption"
	"testing"
)

func TestCreateClient_Success(t *testing.T) {
	mockRepo := clients.NewClientRepositoryMock()
	mockRepo.CreateClientFunc = func(client *clients.Client) (int, error) {
		return 1, nil
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
	repo := NewEncryptedClientRepo(mockRepo, keyManager)
	original := &clients.Client{
		ID: 1,
	}

	id, err := repo.CreateClient(original)
	test.RequireErrNil(t, err)

	if id != 1 {
		t.Errorf("expected ID=1, got %v", id)
	}
}

func TestCreateClient_RepoError(t *testing.T) {
	mockRepo := clients.NewClientRepositoryMock()
	mockRepo.CreateClientFunc = func(client *clients.Client) (int, error) {
		return 1, errors.New("repo error")
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
	repo := NewEncryptedClientRepo(mockRepo, keyManager)
	original := &clients.Client{
		ID: 1,
	}

	_, err = repo.CreateClient(original)

	test.RequireErrNotNil(t, err)
	test.RequireErrContains(t, err, "repo error")
}

func TestGetClient_Success(t *testing.T) {
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
	original := &clients.Client{
		ID:               1,
		Clientname:       "clientname",
		HashedClientname: "hashedClientname",
		Password:         "password",
		Role:             "role",
	}
	var u clients.Client
	err = EncryptFields(&u, original, keyManager)
	test.RequireErrNil(t, err)

	mockRepo := clients.NewClientRepositoryMock()
	mockRepo.GetClientFunc = func(id int) (*clients.Client, error) {
		return &u, nil
	}

	repo := NewEncryptedClientRepo(mockRepo, keyManager)

	retrieved, err := repo.GetClient(1)

	test.RequireErrNil(t, err)

	if *retrieved != *original {
		t.Errorf("expected %v, got %v", original, retrieved)
	}
}

func TestGetClient_RepoError(t *testing.T) {
	keyManager := mocks.NewKeyManagerMock()
	mockRepo := clients.NewClientRepositoryMock()
	mockRepo.GetClientFunc = func(id int) (*clients.Client, error) {
		return nil, errors.New("repo error")
	}

	repo := NewEncryptedClientRepo(mockRepo, keyManager)

	_, err := repo.GetClient(1)

	test.RequireErrNotNil(t, err)
	test.RequireErrContains(t, err, "repo error")
}

func TestGetAllClients_Success(t *testing.T) {
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
	original := &clients.Client{
		ID:               1,
		Clientname:       "clientname",
		HashedClientname: "hashedClientname",
		Password:         "password",
		Role:             "role",
	}
	var u clients.Client
	err = EncryptFields(&u, original, keyManager)
	test.RequireErrNil(t, err)

	mockRepo := clients.NewClientRepositoryMock()
	mockRepo.GetAllFunc = func() ([]clients.Client, error) {
		return []clients.Client{
			u,
		}, nil
	}

	repo := NewEncryptedClientRepo(mockRepo, keyManager)

	retrieved, err := repo.GetAll()
	test.RequireErrNil(t, err)

	if len(retrieved) != 1 {
		t.Fatalf("expected length 1, got %v", len(retrieved))
	}

	if retrieved[0].ID != 1 || retrieved[0].Clientname != "clientname" {
		t.Errorf("expected ID=1 and clientname='clientname', got %v", retrieved[0])
	}
}

func TestGetAllClients_RepoError(t *testing.T) {
	keyManager := mocks.NewKeyManagerMock()
	mockRepo := clients.NewClientRepositoryMock()
	mockRepo.GetAllFunc = func() ([]clients.Client, error) {
		return nil, errors.New("repo error")
	}

	repo := NewEncryptedClientRepo(mockRepo, keyManager)

	_, err := repo.GetAll()
	test.RequireErrNotNil(t, err)

	test.RequireContains(t, err.Error(), "repo error")
}

func TestDeleteClient_Success(t *testing.T) {
	keyManager := mocks.NewKeyManagerMock()
	mockRepo := clients.NewClientRepositoryMock()
	mockRepo.DeleteFunc = func(x int) error {
		return nil
	}

	repo := NewEncryptedClientRepo(mockRepo, keyManager)

	if err := repo.Delete(1); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestDeleteClient_RepoError(t *testing.T) {
	keyManager := mocks.NewKeyManagerMock()
	mockRepo := clients.NewClientRepositoryMock()
	mockRepo.DeleteFunc = func(x int) error {
		return errors.New("repo error")
	}

	repo := NewEncryptedClientRepo(mockRepo, keyManager)

	err := repo.Delete(1)
	if err == nil {
		t.Fatal("expected error, got nil")
	}

	test.RequireContains(t, err.Error(), "repo error")
}

func TestFindByHashedClientname_Success(t *testing.T) {
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
	original := &clients.Client{
		ID:               1,
		Clientname:       "clientname",
		HashedClientname: "hashedClientname",
		Password:         "password",
		Role:             "role",
	}
	var u clients.Client
	err = EncryptFields(&u, original, keyManager)
	test.RequireErrNil(t, err)

	mockRepo := clients.NewClientRepositoryMock()
	mockRepo.FindByHashedClientnameFunc = func(e string) (*clients.Client, error) {
		return &u, nil
	}

	repo := NewEncryptedClientRepo(mockRepo, keyManager)

	retrieved, err := repo.FindByHashedClientname("email")
	test.RequireErrNil(t, err)

	if *retrieved != *original {
		t.Errorf("expected %v, got %v", original, retrieved)
	}
}

func TestFindByHashedClientname_RepoError(t *testing.T) {
	keyManager := mocks.NewKeyManagerMock()
	mockRepo := clients.NewClientRepositoryMock()
	mockRepo.FindByHashedClientnameFunc = func(e string) (*clients.Client, error) {
		return nil, errors.New("repo error")
	}

	repo := NewEncryptedClientRepo(mockRepo, keyManager)

	_, err := repo.FindByHashedClientname("email")

	test.RequireErrNotNil(t, err)
	test.RequireErrContains(t, err, "repo error")
}

func TestUpdateRole_Success(t *testing.T) {
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

	mockRepo := clients.NewClientRepositoryMock()
	mockRepo.UpdateRoleFunc = func(id int, role string) error {
		return nil
	}

	repo := NewEncryptedClientRepo(mockRepo, keyManager)

	err = repo.UpdateRole(1, "role")

	test.RequireErrNil(t, err)
}

func TestUpdateRole_RepoError(t *testing.T) {
	keyManager := mocks.NewKeyManagerMock()
	dbKey, err := encryption.GenerateKey(32)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	keyManager.DBKeyFunc = func() []byte {
		return dbKey
	}
	mockRepo := clients.NewClientRepositoryMock()
	mockRepo.UpdateRoleFunc = func(id int, role string) error {
		return errors.New("repo error")
	}

	repo := NewEncryptedClientRepo(mockRepo, keyManager)

	err = repo.UpdateRole(1, "role")

	test.RequireErrNotNil(t, err)
	test.RequireErrContains(t, err, "repo error")
}

func TestGetRole_Success(t *testing.T) {
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

	encRole, err := EncryptString("role", dbKey)
	test.RequireErrNil(t, err)

	mockRepo := clients.NewClientRepositoryMock()
	mockRepo.GetRoleFunc = func(id int) (string, error) {
		return encRole, nil
	}

	repo := NewEncryptedClientRepo(mockRepo, keyManager)

	role, err := repo.GetRole(1)

	test.RequireErrNil(t, err)
	if role != "role" {
		t.Errorf("expected 'role', got %s", role)
	}
}

func TestGetRole_RepoError(t *testing.T) {
	keyManager := mocks.NewKeyManagerMock()
	mockRepo := clients.NewClientRepositoryMock()
	mockRepo.GetRoleFunc = func(id int) (string, error) {
		return "", errors.New("repo error")
	}

	repo := NewEncryptedClientRepo(mockRepo, keyManager)

	_, err := repo.GetRole(1)

	test.RequireErrNotNil(t, err)
	test.RequireErrContains(t, err, "repo error")
}
