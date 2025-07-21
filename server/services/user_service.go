package services

import (
	"kms/storage"
	"kms/utils/kmsErrors"
)

type UserService struct {
	UserRepo 	storage.UserRepository
}

func NewUserService(userRepo storage.UserRepository) *UserService {
	return &UserService{UserRepo: userRepo}
}

func (s *UserService) GetAll() ([]storage.User, *kmsErrors.AppError) {
	users, err := s.UserRepo.GetAll()
	if err != nil {
		return nil, kmsErrors.MapRepoErr(err)
	}
	return users, nil
}