package clients

import (
	c "kms/internal/bootstrap/context"
	kmsErrors "kms/pkg/errors"
)

type Service struct {
	ClientRepo ClientRepository
	Logger     c.Logger
}

func NewService(clientRepo ClientRepository, logger c.Logger) *Service {
	return &Service{
		ClientRepo: clientRepo,
		Logger:     logger,
	}
}

type ClientRepository interface {
	CreateClient(client *Client) (int, error)
	GetClient(id int) (*Client, error)
	GetAll() ([]Client, error)
	Delete(clientId int) error
	FindByHashedClientname(email string) (*Client, error)
	UpdateRole(id int, role string) error
	GetRole(id int) (string, error)
}

func (s *Service) GetAll() ([]Client, *kmsErrors.AppError) {
	clients, err := s.ClientRepo.GetAll()
	if err != nil {
		return nil, kmsErrors.MapRepoErr(err)
	}
	return clients, nil
}
