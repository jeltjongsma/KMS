package users

import (
	"errors"
	"kms/internal/test/mocks"
	"testing"
)

func TestService_GetAll_Success(t *testing.T) {
	mockRepo := NewUserRepositoryMock()
	mockRepo.GetAllFunc = func() ([]User, error) {
		return []User{{Username: "testuser"}}, nil
	}
	mockLogger := mocks.NewLoggerMock()
	service := NewService(mockRepo, mockLogger)
	users, err := service.GetAll()
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if len(users) != 1 || users[0].Username != "testuser" {
		t.Errorf("expected one user with username 'testuser', got %v", users)
	}
}

func TestService_GetAll_Error(t *testing.T) {
	mockRepo := NewUserRepositoryMock()
	mockRepo.GetAllFunc = func() ([]User, error) {
		return nil, errors.New("repo error")
	}
	mockLogger := mocks.NewLoggerMock()
	service := NewService(mockRepo, mockLogger)
	_, err := service.GetAll()
	if err == nil {
		t.Fatal("expected an error, got nil")
	}
}
