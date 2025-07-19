package services

import (
	"kms/infra"
	"kms/storage"
	"kms/server/dto"
	"kms/utils/kmsErrors"
	"kms/utils/hashing"
	"kms/server/auth"
)

type AuthService struct {
	Cfg 		infra.KmsConfig
	UserRepo 	storage.UserRepository
}

func NewAuthService(cfg infra.KmsConfig, userRepo storage.UserRepository) *AuthService {
	return &AuthService{
		Cfg: cfg,
		UserRepo: userRepo,
	}
}

func (s *AuthService) Signup(cred *dto.Credentials) (string, *kmsErrors.AppError) {
	hashedPassword, err := hashing.HashPassword(cred.Password)
	if err != nil {
		return "", kmsErrors.NewAppError(err, "Failed to hash password", 500)
	}

	user := cred.Lift()

	user.Password = hashedPassword
	
	// TODO: Implement proper HandleRepoErr to catch 404's etc.
	id, err := s.UserRepo.CreateUser(&user)
	if err != nil {
		return "", kmsErrors.NewAppError(err, "Failed to store user", 500)
	}

	user.ID = id

	jwt, err := auth.GenerateJWT(s.Cfg, &user)
	if err != nil {
		return "", kmsErrors.NewAppError(err, "Failed to generate JWT", 500)
	}
	
	return jwt, nil
}

func (s *AuthService) Login(cred *dto.Credentials) (string, *kmsErrors.AppError) {
	user, err := s.UserRepo.FindByEmail(cred.Email)
	if err != nil {
		return "", kmsErrors.NewAppError(err, "Failed to get user", 500)
	}

	if err := hashing.CheckPassword(user.Password, cred.Password); err != nil {
		return "", kmsErrors.NewAppError(err, "Incorrect password", 401)
	}

	jwt, err := auth.GenerateJWT(s.Cfg, user) 
	if err != nil {
		return "", kmsErrors.NewAppError(err, "Failed to generate JWT", 500)
	}

	return jwt, nil
}