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
	Cfg 			infra.KmsConfig
	UserRepo 		storage.UserRepository
	TokenGenInfo 	*auth.TokenGenInfo
	TokenSecret		[]byte
}

func NewAuthService(
	cfg infra.KmsConfig, 
	userRepo storage.UserRepository, 
	tokenGenInfo *auth.TokenGenInfo,
	tokenSecret []byte,
	) *AuthService {
	return &AuthService{
		Cfg: cfg,
		UserRepo: userRepo,
		TokenGenInfo: tokenGenInfo,
		TokenSecret: tokenSecret,
	}
}

func (s *AuthService) Signup(cred *dto.SignupCredentials) (string, *kmsErrors.AppError) {
	token, err := auth.VerifyToken(cred.Token, s.TokenSecret)
	if err != nil {
		return "", kmsErrors.MapVerifyTokenErr(err)
	}

	if token.Header.Typ != "signup" {
		return "", kmsErrors.NewAppError(
			kmsErrors.WrapError(kmsErrors.ErrInvalidToken, map[string]interface{}{
				"msg": "Token should be of type 'signup'",
				"type": token.Header.Typ, 
			}),
			"Invalid token",
			400,
		)
	}

	hashedPassword, err := hashing.HashPassword(cred.Password)
	if err != nil {
		return "", kmsErrors.MapHashErr(err)
	}

	user := &storage.User{
		Username: token.Payload.Sub,
		Password: hashedPassword,
		Role: s.Cfg["DEFAULT_ROLE"],
	}
	
	id, err := s.UserRepo.CreateUser(user)
	if err != nil {
		return "", kmsErrors.MapRepoErr(err)
	}

	user.ID = id

	jwt, err := auth.GenerateJWT(s.TokenGenInfo, user)
	if err != nil {
		return "", kmsErrors.NewInternalServerError(err)
	}
	
	return jwt, nil
}

func (s *AuthService) Login(cred *dto.Credentials) (string, *kmsErrors.AppError) {
	user, err := s.UserRepo.FindByUsername(cred.Username)
	if err != nil {
		// Check if err is "not found" to help prevent user enumeration attacks
		if errors.Is(err, sql.ErrNoRows) {
			return "", kmsErrors.NewAppError(err, "Incorrect username or password", 401)
		}
		return "", kmsErrors.MapRepoErr(err)
	}

	if err := hashing.CheckPassword(user.Password, cred.Password); err != nil {
		return "", kmsErrors.MapHashErr(err)
	}

	jwt, err := auth.GenerateJWT(s.TokenGenInfo, user) 
	if err != nil {
		return "", kmsErrors.NewInternalServerError(err)
	}

	return jwt, nil
}