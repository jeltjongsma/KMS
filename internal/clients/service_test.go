package clients

import (
	"errors"
	"kms/internal/test/mocks"
	"testing"
)

func TestService_GetAll_Success(t *testing.T) {
	mockRepo := NewClientRepositoryMock()
	mockRepo.GetAllFunc = func() ([]Client, error) {
		return []Client{{Clientname: "testclient"}}, nil
	}
	mockLogger := mocks.NewLoggerMock()
	service := NewService(mockRepo, mockLogger)
	clients, err := service.GetAll()
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if len(clients) != 1 || clients[0].Clientname != "testclient" {
		t.Errorf("expected one client with clientname 'testclient', got %v", clients)
	}
}

func TestService_GetAll_Error(t *testing.T) {
	mockRepo := NewClientRepositoryMock()
	mockRepo.GetAllFunc = func() ([]Client, error) {
		return nil, errors.New("repo error")
	}
	mockLogger := mocks.NewLoggerMock()
	service := NewService(mockRepo, mockLogger)
	_, err := service.GetAll()
	if err == nil {
		t.Fatal("expected an error, got nil")
	}
}
