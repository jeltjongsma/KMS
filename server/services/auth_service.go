package services

import (
	"kms/infra"
	"kms/storage"
	"kms/server/dto"
	"kms/utils/kmsErrors"
	"kms/utils/hashing"
	"kms/server/auth"
	"database/sql"
	"errors"
)

type AuthService struct {
	Cfg 		infra.KmsConfig
	UserRepo 	storage.UserRepository
	JWTGenInfo 	*auth.JWTGenInfo
}

func NewAuthService(cfg infra.KmsConfig, userRepo storage.UserRepository, jwtGenInfo *auth.JWTGenInfo) *AuthService {
	
	return &AuthService{
		Cfg: cfg,
		UserRepo: userRepo,
		JWTGenInfo: jwtGenInfo,
	}
}

func (s *AuthService) Signup(cred *dto.Credentials) (string, *kmsErrors.AppError) {
	hashedPassword, err := hashing.HashPassword(cred.Password)
	if err != nil {
		return "", kmsErrors.MapHashErr(err)
	}

	user := cred.Lift()

	user.Password = hashedPassword
	user.Role = s.Cfg["DEFAULT_ROLE"]
	
	id, err := s.UserRepo.CreateUser(user)
	if err != nil {
		return "", kmsErrors.MapRepoErr(err)
	}

	user.ID = id

	

	jwt, err := auth.GenerateJWT(s.JWTGenInfo, user)
	if err != nil {
		return "", kmsErrors.NewInternalServerError(err)
	}
	
	return jwt, nil
}

func (s *AuthService) Login(cred *dto.Credentials) (string, *kmsErrors.AppError) {
	user, err := s.UserRepo.FindByEmail(cred.Email)
	if err != nil {
		// Check if err is "not found" to help prevent user enumeration attacks
		if errors.Is(err, sql.ErrNoRows) {
			return "", kmsErrors.NewAppError(err, "Incorrect email or password", 401)
		}
		return "", kmsErrors.MapRepoErr(err)
	}

	if err := hashing.CheckPassword(user.Password, cred.Password); err != nil {
		return "", kmsErrors.MapHashErr(err)
	}

	jwt, err := auth.GenerateJWT(s.JWTGenInfo, user) 
	if err != nil {
		return "", kmsErrors.NewInternalServerError(err)
	}

	return jwt, nil
}