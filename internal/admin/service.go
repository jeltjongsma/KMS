package admin

import (
	"kms/internal/users"
	kmsErrors "kms/pkg/errors"
	"kms/internal/auth"
)

type Service struct {
	AdminRepo 	AdminRepository
	UserRepo 	users.UserRepository
	TokenSecret []byte
}

func NewService(adminRepo AdminRepository, userRepo users.UserRepository, tokenSecret []byte) *Service {
	return &Service{
		AdminRepo: adminRepo,
		UserRepo: userRepo,
		TokenSecret: tokenSecret,
	}
}

type AdminRepository interface {
	GetAdmin(id int) (*users.User, error)
}

func (s *Service) UpdateRole(userId int, role string) *kmsErrors.AppError {
	if err := s.UserRepo.UpdateRole(userId, role); err != nil {
		return kmsErrors.MapRepoErr(err)
	}
	return nil
}

func (s *Service) Me(userId int) (*users.User, *kmsErrors.AppError) {
	admin, err := s.UserRepo.GetUser(userId)
	if err != nil {
		return nil, kmsErrors.MapRepoErr(err)
	}
	return admin, nil
}

func (s *Service) GenerateSignupToken(body *GenerateSignupTokenRequest) (string, *kmsErrors.AppError) {
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