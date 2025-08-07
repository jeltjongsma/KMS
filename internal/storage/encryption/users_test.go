package encryption

import (
	"errors"
	"kms/internal/test"
	"kms/internal/test/mocks"
	"kms/internal/users"
	"kms/pkg/encryption"
	"testing"
)

func TestCreateUser_Success(t *testing.T) {
	mockRepo := users.NewUserRepositoryMock()
	mockRepo.CreateUserFunc = func(user *users.User) (int, error) {
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
	repo := NewEncryptedUserRepo(mockRepo, keyManager)
	original := &users.User{
		ID: 1,
	}

	id, err := repo.CreateUser(original)
	test.RequireErrNil(t, err)

	if id != 1 {
		t.Errorf("expected ID=1, got %v", id)
	}
}

func TestCreateUser_RepoError(t *testing.T) {
	mockRepo := users.NewUserRepositoryMock()
	mockRepo.CreateUserFunc = func(user *users.User) (int, error) {
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
	repo := NewEncryptedUserRepo(mockRepo, keyManager)
	original := &users.User{
		ID: 1,
	}

	_, err = repo.CreateUser(original)

	test.RequireErrNotNil(t, err)
	test.RequireErrContains(t, err, "repo error")
}

func TestGetUser_Success(t *testing.T) {
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
	original := &users.User{
		ID:             1,
		Username:       "username",
		HashedUsername: "hashedUsername",
		Password:       "password",
		Role:           "role",
	}
	var u users.User
	err = EncryptFields(&u, original, keyManager)
	test.RequireErrNil(t, err)

	mockRepo := users.NewUserRepositoryMock()
	mockRepo.GetUserFunc = func(id int) (*users.User, error) {
		return &u, nil
	}

	repo := NewEncryptedUserRepo(mockRepo, keyManager)

	retrieved, err := repo.GetUser(1)

	test.RequireErrNil(t, err)

	if *retrieved != *original {
		t.Errorf("expected %v, got %v", original, retrieved)
	}
}

func TestGetUser_RepoError(t *testing.T) {
	keyManager := mocks.NewKeyManagerMock()
	mockRepo := users.NewUserRepositoryMock()
	mockRepo.GetUserFunc = func(id int) (*users.User, error) {
		return nil, errors.New("repo error")
	}

	repo := NewEncryptedUserRepo(mockRepo, keyManager)

	_, err := repo.GetUser(1)

	test.RequireErrNotNil(t, err)
	test.RequireErrContains(t, err, "repo error")
}

func TestGetAllUsers_Success(t *testing.T) {
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
	original := &users.User{
		ID:             1,
		Username:       "username",
		HashedUsername: "hashedUsername",
		Password:       "password",
		Role:           "role",
	}
	var u users.User
	err = EncryptFields(&u, original, keyManager)
	test.RequireErrNil(t, err)

	mockRepo := users.NewUserRepositoryMock()
	mockRepo.GetAllFunc = func() ([]users.User, error) {
		return []users.User{
			u,
		}, nil
	}

	repo := NewEncryptedUserRepo(mockRepo, keyManager)

	retrieved, err := repo.GetAll()
	test.RequireErrNil(t, err)

	if len(retrieved) != 1 {
		t.Fatalf("expected length 1, got %v", len(retrieved))
	}

	if retrieved[0].ID != 1 || retrieved[0].Username != "username" {
		t.Errorf("expected ID=1 and username='username', got %v", retrieved[0])
	}
}

func TestGetAllUsers_RepoError(t *testing.T) {
	keyManager := mocks.NewKeyManagerMock()
	mockRepo := users.NewUserRepositoryMock()
	mockRepo.GetAllFunc = func() ([]users.User, error) {
		return nil, errors.New("repo error")
	}

	repo := NewEncryptedUserRepo(mockRepo, keyManager)

	_, err := repo.GetAll()
	test.RequireErrNotNil(t, err)

	test.RequireContains(t, err.Error(), "repo error")
}

func TestFindByHashedUsername_Success(t *testing.T) {
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
	original := &users.User{
		ID:             1,
		Username:       "username",
		HashedUsername: "hashedUsername",
		Password:       "password",
		Role:           "role",
	}
	var u users.User
	err = EncryptFields(&u, original, keyManager)
	test.RequireErrNil(t, err)

	mockRepo := users.NewUserRepositoryMock()
	mockRepo.FindByHashedUsernameFunc = func(e string) (*users.User, error) {
		return &u, nil
	}

	repo := NewEncryptedUserRepo(mockRepo, keyManager)

	retrieved, err := repo.FindByHashedUsername("email")
	test.RequireErrNil(t, err)

	if *retrieved != *original {
		t.Errorf("expected %v, got %v", original, retrieved)
	}
}

func TestFindByHashedUsername_RepoError(t *testing.T) {
	keyManager := mocks.NewKeyManagerMock()
	mockRepo := users.NewUserRepositoryMock()
	mockRepo.FindByHashedUsernameFunc = func(e string) (*users.User, error) {
		return nil, errors.New("repo error")
	}

	repo := NewEncryptedUserRepo(mockRepo, keyManager)

	_, err := repo.FindByHashedUsername("email")

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

	mockRepo := users.NewUserRepositoryMock()
	mockRepo.UpdateRoleFunc = func(id int, role string) error {
		return nil
	}

	repo := NewEncryptedUserRepo(mockRepo, keyManager)

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
	mockRepo := users.NewUserRepositoryMock()
	mockRepo.UpdateRoleFunc = func(id int, role string) error {
		return errors.New("repo error")
	}

	repo := NewEncryptedUserRepo(mockRepo, keyManager)

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

	mockRepo := users.NewUserRepositoryMock()
	mockRepo.GetRoleFunc = func(id int) (string, error) {
		return encRole, nil
	}

	repo := NewEncryptedUserRepo(mockRepo, keyManager)

	role, err := repo.GetRole(1)

	test.RequireErrNil(t, err)
	if role != "role" {
		t.Errorf("expected 'role', got %s", role)
	}
}

func TestGetRole_RepoError(t *testing.T) {
	keyManager := mocks.NewKeyManagerMock()
	mockRepo := users.NewUserRepositoryMock()
	mockRepo.GetRoleFunc = func(id int) (string, error) {
		return "", errors.New("repo error")
	}

	repo := NewEncryptedUserRepo(mockRepo, keyManager)

	_, err := repo.GetRole(1)

	test.RequireErrNotNil(t, err)
	test.RequireErrContains(t, err, "repo error")
}
