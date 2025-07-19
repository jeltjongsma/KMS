package services

import (
	"kms/storage"
	"kms/utils/kmsErrors"
)

type AdminService struct {
	AdminRepo 	storage.AdminRepository
	UserRepo 	storage.UserRepository
}

func NewAdminService(adminRepo storage.AdminRepository, userRepo storage.UserRepository) *AdminService {
	return &AdminService{
		AdminRepo: adminRepo,
		UserRepo: userRepo,
	}
}

func (s *AdminService) UpdateRole(userId int, role string) *kmsErrors.AppError {
	if err := s.UserRepo.UpdateRole(userId, role); err != nil {
		return kmsErrors.NewAppError(err, "Failed to update role", 500)
	}
	return nil
}

func (s *AdminService) Me(userId int) (*storage.User, *kmsErrors.AppError) {
	admin, err := s.UserRepo.GetUser(userId)
	if err != nil {
		return nil, kmsErrors.NewAppError(err, "Failed to retrieve admin", 500)
	}
	return admin, nil
}