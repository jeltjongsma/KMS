package admin

import (
	"errors"
	"kms/internal/test"
	"kms/internal/test/mocks"
	"kms/internal/users"
	"strings"
	"testing"
)

func TestService_UpdateRole_Success(t *testing.T) {
	mockRepo := NewAdminRepositoryMock()
	mockUserRepo := users.NewUserRepositoryMock()
	mockLogger := mocks.NewLoggerMock()

	mockUserRepo.GetRoleFunc = func(userId int) (string, error) {
		return "user", nil
	}
	mockUserRepo.UpdateRoleFunc = func(userId int, role string) error {
		return nil
	}

	service := NewService(mockRepo, mockUserRepo, nil, mockLogger)
	err := service.UpdateRole(1, "admin", "admin123")
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
}

func TestService_UpdateRole_RepoGetRoleError(t *testing.T) {
	mockRepo := NewAdminRepositoryMock()
	mockUserRepo := users.NewUserRepositoryMock()
	mockLogger := mocks.NewLoggerMock()

	mockUserRepo.GetRoleFunc = func(userId int) (string, error) {
		return "", errors.New("repo error")
	}

	service := NewService(mockRepo, mockUserRepo, nil, mockLogger)
	err := service.UpdateRole(1, "admin", "admin123")
	if err == nil || !strings.Contains(err.Err.Error(), "repo error") {
		t.Fatalf("expected repo error, got %v", err)
	}
	if err.Code != 500 {
		t.Errorf("expected error code 500, got %d", err.Code)
	}
}

func TestService_UpdateRole_RepoUpdateRoleError(t *testing.T) {
	mockRepo := NewAdminRepositoryMock()
	mockUserRepo := users.NewUserRepositoryMock()
	mockLogger := mocks.NewLoggerMock()

	mockUserRepo.GetRoleFunc = func(userId int) (string, error) {
		return "user", nil
	}
	mockUserRepo.UpdateRoleFunc = func(userId int, role string) error {
		return errors.New("update error")
	}

	service := NewService(mockRepo, mockUserRepo, nil, mockLogger)
	err := service.UpdateRole(1, "admin", "admin123")
	if err == nil || !strings.Contains(err.Err.Error(), "update error") {
		t.Fatalf("expected update error, got %v", err)
	}
	if err.Code != 500 {
		t.Errorf("expected error code 500, got %d", err.Code)
	}
}

func TestService_Me_Success(t *testing.T) {
	mockRepo := NewAdminRepositoryMock()
	mockUserRepo := users.NewUserRepositoryMock()
	mockLogger := mocks.NewLoggerMock()

	mockUserRepo.GetUserFunc = func(userId int) (*users.User, error) {
		return &users.User{Username: "username", Role: "admin"}, nil
	}

	service := NewService(mockRepo, mockUserRepo, nil, mockLogger)
	admin, err := service.Me(1)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if admin.Role != "admin" {
		t.Errorf("expected role 'admin', got %s", admin.Role)
	}
	if admin.Username != "username" {
		t.Errorf("expected username 'username', got %s", admin.Username)
	}
}

func TestService_Me_Error(t *testing.T) {
	mockRepo := NewAdminRepositoryMock()
	mockUserRepo := users.NewUserRepositoryMock()
	mockLogger := mocks.NewLoggerMock()

	mockUserRepo.GetUserFunc = func(userId int) (*users.User, error) {
		return nil, errors.New("repo error")
	}

	service := NewService(mockRepo, mockUserRepo, nil, mockLogger)
	admin, err := service.Me(1)
	if admin != nil {
		t.Fatalf("expected nil admin, got %v", admin)
	}
	if err == nil || !strings.Contains(err.Err.Error(), "repo error") {
		t.Fatalf("expected repo error, got %v", err)
	}
	if err.Code != 500 {
		t.Errorf("expected error code 500, got %d", err.Code)
	}
}

func TestService_GenerateSignupToken_Success(t *testing.T) {
	mockRepo := NewAdminRepositoryMock()
	mockUserRepo := users.NewUserRepositoryMock()
	mockLogger := mocks.NewLoggerMock()
	mockKeyManager := mocks.NewKeyManagerMock()

	mockKeyManager.SignupKeyFunc = func() []byte {
		return []byte("test-signup-key")
	}

	service := NewService(mockRepo, mockUserRepo, mockKeyManager, mockLogger)
	body := &GenerateSignupTokenRequest{
		Username: "testuser",
		Ttl:      3600,
	}
	token, err := service.GenerateSignupToken(body, "admin123")
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if token == "" {
		t.Error("expected non-empty token")
	}
}

func TestService_GenerateSignupToken_validateUsernameError(t *testing.T) {
	mockRepo := NewAdminRepositoryMock()
	mockUserRepo := users.NewUserRepositoryMock()
	mockLogger := mocks.NewLoggerMock()
	mockKeyManager := mocks.NewKeyManagerMock()

	service := NewService(mockRepo, mockUserRepo, mockKeyManager, mockLogger)
	body := &GenerateSignupTokenRequest{
		Username: "invalid@user",
		Ttl:      3600,
	}
	_, err := service.GenerateSignupToken(body, "admin123")
	if err == nil || !strings.Contains(err.Err.Error(), "invalid character in username") {
		t.Fatalf("expected invalid username error, got %v", err)
	}
	if err.Code != 400 {
		t.Errorf("expected error code 400, got %d", err.Code)
	}
}

func TestService_validateUsername(t *testing.T) {
	tests := []struct {
		username    string
		expectError bool
	}{
		{"validUser", false},
		{"valid-user123", false},
		{"invalid@user", true},
		{"", true},
		{"abc", true},
		{"valid-key-with-maximum-length-12345678901234567890123456789012345678901234567890123456789012345678901234567890", true},
	}
	for _, tt := range tests {
		err := validateUsername(tt.username)
		if (err != nil) != tt.expectError {
			t.Errorf("validateUsername(%q) error = %v, expectError %v", tt.username, err, tt.expectError)
			continue
		}
	}
}

func TestService_GetUsers_Success(t *testing.T) {
	mockAdminRepo := NewAdminRepositoryMock()
	mockUserRepo := users.NewUserRepositoryMock()
	mockUserRepo.GetAllFunc = func() ([]users.User, error) {
		return []users.User{
			{ID: 1, Username: "username"},
		}, nil
	}
	mockKeyManager := mocks.NewKeyManagerMock()
	mockLogger := mocks.NewLoggerMock()

	service := NewService(mockAdminRepo, mockUserRepo, mockKeyManager, mockLogger)

	u, err := service.GetUsers()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(u) != 1 {
		t.Errorf("expected length 1, got %d", len(u))
	}

	if u[0].ID != 1 || u[0].Username != "username" {
		t.Errorf("expected ID=1 and Username='username', got %v", u[0])
	}
}

func TestService_GetUsers_RepoError(t *testing.T) {
	mockAdminRepo := NewAdminRepositoryMock()
	mockUserRepo := users.NewUserRepositoryMock()
	mockUserRepo.GetAllFunc = func() ([]users.User, error) {
		return nil, errors.New("repo error")
	}
	mockKeyManager := mocks.NewKeyManagerMock()
	mockLogger := mocks.NewLoggerMock()

	service := NewService(mockAdminRepo, mockUserRepo, mockKeyManager, mockLogger)

	_, err := service.GetUsers()
	if err == nil {
		t.Fatal("expected repo error, got nil")
	}

	test.RequireContains(t, err.Err.Error(), "repo error")
}

func TestService_DeleteUser_Success(t *testing.T) {
	mockAdminRepo := NewAdminRepositoryMock()
	mockUserRepo := users.NewUserRepositoryMock()
	mockUserRepo.DeleteFunc = func(userId int) error {
		return nil
	}
	mockKeyManager := mocks.NewKeyManagerMock()
	mockLogger := mocks.NewLoggerMock()

	service := NewService(mockAdminRepo, mockUserRepo, mockKeyManager, mockLogger)

	if err := service.DeleteUser(1); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestService_DeleteUser_RepoError(t *testing.T) {
	mockAdminRepo := NewAdminRepositoryMock()
	mockUserRepo := users.NewUserRepositoryMock()
	mockUserRepo.DeleteFunc = func(userId int) error {
		return errors.New("repo error")
	}
	mockKeyManager := mocks.NewKeyManagerMock()
	mockLogger := mocks.NewLoggerMock()

	service := NewService(mockAdminRepo, mockUserRepo, mockKeyManager, mockLogger)

	err := service.DeleteUser(1)

	if err == nil {
		t.Fatal("expected error")
	}

	test.RequireContains(t, err.Err.Error(), "repo error")
}
