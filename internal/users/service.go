package users

import (
	kmsErrors "kms/pkg/errors"
	c "kms/internal/bootstrap/context"
)

type Service struct {
	UserRepo 	UserRepository
	Logger 		c.Logger
}

func NewService(userRepo UserRepository, logger c.Logger) *Service {
	return &Service{
		UserRepo: userRepo,
		Logger: logger,
	}
}

type UserRepository interface {
	CreateUser(user *User) (int, error)
	GetUser(id int) (*User, error)
	GetAll() ([]User, error)
	FindByHashedUsername(email string) (*User, error)
	UpdateRole(id int, role string) error
	GetRole(id int) (string, error)
}

func (s *Service) GetAll() ([]User, *kmsErrors.AppError) {
	users, err := s.UserRepo.GetAll()
	if err != nil {
		return nil, kmsErrors.MapRepoErr(err)
	}
	return users, nil
}