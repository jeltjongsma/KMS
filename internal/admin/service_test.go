package admin

import (
	"errors"
	"kms/internal/clients"
	"kms/internal/test"
	"kms/internal/test/mocks"
	"strings"
	"testing"
)

func TestService_UpdateRole_Success(t *testing.T) {
	mockRepo := NewAdminRepositoryMock()
	mockClientRepo := clients.NewClientRepositoryMock()
	mockLogger := mocks.NewLoggerMock()

	mockClientRepo.GetRoleFunc = func(clientId int) (string, error) {
		return "client", nil
	}
	mockClientRepo.UpdateRoleFunc = func(clientId int, role string) error {
		return nil
	}

	service := NewService(mockRepo, mockClientRepo, nil, mockLogger)
	err := service.UpdateRole(1, "admin", "admin123")
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
}

func TestService_UpdateRole_RepoGetRoleError(t *testing.T) {
	mockRepo := NewAdminRepositoryMock()
	mockClientRepo := clients.NewClientRepositoryMock()
	mockLogger := mocks.NewLoggerMock()

	mockClientRepo.GetRoleFunc = func(clientId int) (string, error) {
		return "", errors.New("repo error")
	}

	service := NewService(mockRepo, mockClientRepo, nil, mockLogger)
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
	mockClientRepo := clients.NewClientRepositoryMock()
	mockLogger := mocks.NewLoggerMock()

	mockClientRepo.GetRoleFunc = func(clientId int) (string, error) {
		return "client", nil
	}
	mockClientRepo.UpdateRoleFunc = func(clientId int, role string) error {
		return errors.New("update error")
	}

	service := NewService(mockRepo, mockClientRepo, nil, mockLogger)
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
	mockClientRepo := clients.NewClientRepositoryMock()
	mockLogger := mocks.NewLoggerMock()

	mockClientRepo.GetClientFunc = func(clientId int) (*clients.Client, error) {
		return &clients.Client{Clientname: "clientname", Role: "admin"}, nil
	}

	service := NewService(mockRepo, mockClientRepo, nil, mockLogger)
	admin, err := service.Me(1)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if admin.Role != "admin" {
		t.Errorf("expected role 'admin', got %s", admin.Role)
	}
	if admin.Clientname != "clientname" {
		t.Errorf("expected clientname 'clientname', got %s", admin.Clientname)
	}
}

func TestService_Me_Error(t *testing.T) {
	mockRepo := NewAdminRepositoryMock()
	mockClientRepo := clients.NewClientRepositoryMock()
	mockLogger := mocks.NewLoggerMock()

	mockClientRepo.GetClientFunc = func(clientId int) (*clients.Client, error) {
		return nil, errors.New("repo error")
	}

	service := NewService(mockRepo, mockClientRepo, nil, mockLogger)
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
	mockClientRepo := clients.NewClientRepositoryMock()
	mockLogger := mocks.NewLoggerMock()
	mockKeyManager := mocks.NewKeyManagerMock()

	mockKeyManager.SignupKeyFunc = func() []byte {
		return []byte("test-signup-key")
	}

	service := NewService(mockRepo, mockClientRepo, mockKeyManager, mockLogger)
	body := &GenerateSignupTokenRequest{
		Clientname: "testclient",
		Ttl:        3600,
	}
	token, err := service.GenerateSignupToken(body, "admin123")
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if token == "" {
		t.Error("expected non-empty token")
	}
}

func TestService_GenerateSignupToken_validateClientnameError(t *testing.T) {
	mockRepo := NewAdminRepositoryMock()
	mockClientRepo := clients.NewClientRepositoryMock()
	mockLogger := mocks.NewLoggerMock()
	mockKeyManager := mocks.NewKeyManagerMock()

	service := NewService(mockRepo, mockClientRepo, mockKeyManager, mockLogger)
	body := &GenerateSignupTokenRequest{
		Clientname: "invalid@client",
		Ttl:        3600,
	}
	_, err := service.GenerateSignupToken(body, "admin123")
	if err == nil || !strings.Contains(err.Err.Error(), "invalid character in clientname") {
		t.Fatalf("expected invalid clientname error, got %v", err)
	}
	if err.Code != 400 {
		t.Errorf("expected error code 400, got %d", err.Code)
	}
}

func TestService_validateClientname(t *testing.T) {
	tests := []struct {
		clientname  string
		expectError bool
	}{
		{"validClient", false},
		{"valid-client123", false},
		{"invalid@client", true},
		{"", true},
		{"abc", true},
		{"valid-key-with-maximum-length-12345678901234567890123456789012345678901234567890123456789012345678901234567890", true},
	}
	for _, tt := range tests {
		err := validateClientname(tt.clientname)
		if (err != nil) != tt.expectError {
			t.Errorf("validateClientname(%q) error = %v, expectError %v", tt.clientname, err, tt.expectError)
			continue
		}
	}
}

func TestService_GetClients_Success(t *testing.T) {
	mockAdminRepo := NewAdminRepositoryMock()
	mockClientRepo := clients.NewClientRepositoryMock()
	mockClientRepo.GetAllFunc = func() ([]clients.Client, error) {
		return []clients.Client{
			{ID: 1, Clientname: "clientname"},
		}, nil
	}
	mockKeyManager := mocks.NewKeyManagerMock()
	mockLogger := mocks.NewLoggerMock()

	service := NewService(mockAdminRepo, mockClientRepo, mockKeyManager, mockLogger)

	u, err := service.GetClients()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(u) != 1 {
		t.Errorf("expected length 1, got %d", len(u))
	}

	if u[0].ID != 1 || u[0].Clientname != "clientname" {
		t.Errorf("expected ID=1 and Clientname='clientname', got %v", u[0])
	}
}

func TestService_GetClients_RepoError(t *testing.T) {
	mockAdminRepo := NewAdminRepositoryMock()
	mockClientRepo := clients.NewClientRepositoryMock()
	mockClientRepo.GetAllFunc = func() ([]clients.Client, error) {
		return nil, errors.New("repo error")
	}
	mockKeyManager := mocks.NewKeyManagerMock()
	mockLogger := mocks.NewLoggerMock()

	service := NewService(mockAdminRepo, mockClientRepo, mockKeyManager, mockLogger)

	_, err := service.GetClients()
	if err == nil {
		t.Fatal("expected repo error, got nil")
	}

	test.RequireContains(t, err.Err.Error(), "repo error")
}

func TestService_DeleteClient_Success(t *testing.T) {
	mockAdminRepo := NewAdminRepositoryMock()
	mockClientRepo := clients.NewClientRepositoryMock()
	mockClientRepo.DeleteFunc = func(clientId int) error {
		return nil
	}
	mockKeyManager := mocks.NewKeyManagerMock()
	mockLogger := mocks.NewLoggerMock()

	service := NewService(mockAdminRepo, mockClientRepo, mockKeyManager, mockLogger)

	if err := service.DeleteClient(1); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestService_DeleteClient_RepoError(t *testing.T) {
	mockAdminRepo := NewAdminRepositoryMock()
	mockClientRepo := clients.NewClientRepositoryMock()
	mockClientRepo.DeleteFunc = func(clientId int) error {
		return errors.New("repo error")
	}
	mockKeyManager := mocks.NewKeyManagerMock()
	mockLogger := mocks.NewLoggerMock()

	service := NewService(mockAdminRepo, mockClientRepo, mockKeyManager, mockLogger)

	err := service.DeleteClient(1)

	if err == nil {
		t.Fatal("expected error")
	}

	test.RequireContains(t, err.Err.Error(), "repo error")
}
