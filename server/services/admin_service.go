package services

import (
	"kms/storage"
	"kms/utils/kmsErrors"
	"kms/server/dto"
	"kms/server/auth"
)

type AdminService struct {
	AdminRepo 	storage.AdminRepository
	UserRepo 	storage.UserRepository
	TokenSecret []byte
}

func NewAdminService(adminRepo storage.AdminRepository, userRepo storage.UserRepository, tokenSecret []byte) *AdminService {
	return &AdminService{
		AdminRepo: adminRepo,
		UserRepo: userRepo,
		TokenSecret: tokenSecret,
	}
}

func (s *AdminService) UpdateRole(userId int, role string) *kmsErrors.AppError {
	if err := s.UserRepo.UpdateRole(userId, role); err != nil {
		return kmsErrors.MapRepoErr(err)
	}
	return nil
}

func (s *AdminService) Me(userId int) (*storage.User, *kmsErrors.AppError) {
	admin, err := s.UserRepo.GetUser(userId)
	if err != nil {
		return nil, kmsErrors.MapRepoErr(err)
	}
	return admin, nil
}

func (s *AdminService) GenerateSignupToken(body *dto.GenerateSignupTokenRequest) (string, *kmsErrors.AppError) {
	tokenGenInfo := &auth.TokenGenInfo{
		Ttl: body.Ttl,
		Secret: s.TokenSecret,
		Typ: "signup",
	}

	token, err := auth.GenerateSignupToken(tokenGenInfo, body.Username)
	if err != nil {
		return "", kmsErrors.NewInternalServerError(err)
	}

	return token, nil
}