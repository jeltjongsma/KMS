package auth

import (
	"database/sql"
	"errors"
	"fmt"
	c "kms/internal/bootstrap/context"
	"kms/internal/users"
	kmsErrors "kms/pkg/errors"
	"kms/pkg/hashing"
	"unicode"
)

type Service struct {
	Cfg          c.KmsConfig
	UserRepo     users.UserRepository
	TokenGenInfo *TokenGenInfo
	KeyManager   c.KeyManager
	Logger       c.Logger
}

func NewService(
	cfg c.KmsConfig,
	userRepo users.UserRepository,
	tokenGenInfo *TokenGenInfo,
	keyManager c.KeyManager,
	logger c.Logger,
) *Service {
	return &Service{
		Cfg:          cfg,
		UserRepo:     userRepo,
		TokenGenInfo: tokenGenInfo,
		KeyManager:   keyManager,
		Logger:       logger,
	}
}

func (s *Service) Signup(cred *SignupCredentials) (string, *kmsErrors.AppError) {
	token, err := VerifyToken(cred.Token, s.KeyManager.SignupKey())
	if err != nil {
		return "", kmsErrors.MapVerifyTokenErr(err)
	}

	if err := validatePassword(cred.Password); err != nil {
		return "", kmsErrors.NewAppError(err, "Password does not meet minimum requirements. 12 <= len <= 128 & contains at least 3 of the following: Upper, lower, sym & digit", 400)
	}

	if token.Header.Typ != "signup" {
		return "", kmsErrors.NewAppError(
			kmsErrors.WrapError(kmsErrors.ErrInvalidToken, map[string]interface{}{
				"msg":  "Token should be of type 'signup'",
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

	usernameSecret, err := s.KeyManager.HashKey("username")
	if err != nil {
		return "", kmsErrors.NewInternalServerError(err)
	}

	user := &users.User{
		Username:       token.Payload.Sub,
		HashedUsername: hashing.HashHS256ToB64([]byte(token.Payload.Sub), usernameSecret),
		Password:       hashedPassword,
		Role:           s.Cfg["DEFAULT_ROLE"],
	}

	id, err := s.UserRepo.CreateUser(user)
	if err != nil {
		return "", kmsErrors.MapRepoErr(err)
	}

	user.ID = id

	jwt, err := GenerateJWT(s.TokenGenInfo, user)
	if err != nil {
		return "", kmsErrors.NewInternalServerError(err)
	}

	s.Logger.Info("User signed up", "userId", id)

	return jwt, nil
}

func (s *Service) Login(cred *Credentials) (string, *kmsErrors.AppError) {
	usernameSecret, err := s.KeyManager.HashKey("username")
	if err != nil {
		return "", kmsErrors.NewInternalServerError(err)
	}

	hashedUsername := hashing.HashHS256ToB64([]byte(cred.Username), usernameSecret)
	user, err := s.UserRepo.FindByHashedUsername(hashedUsername)
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

	jwt, err := GenerateJWT(s.TokenGenInfo, user)
	if err != nil {
		return "", kmsErrors.NewInternalServerError(err)
	}

	s.Logger.Info("User signed in", "userId", user.ID)

	return jwt, nil
}

func validatePassword(password string) error {
	if len(password) < 12 || len(password) > 128 {
		return fmt.Errorf("password length should be between 12 and 128, is %d", len(password))
	}
	var (
		hasLower, hasUpper, hasDigit, hasSym bool
	)

	for _, r := range password {
		switch {
		case unicode.IsLower(r):
			hasLower = true
		case unicode.IsUpper(r):
			hasUpper = true
		case unicode.IsDigit(r):
			hasDigit = true
		case unicode.IsPunct(r) || unicode.IsSymbol(r):
			hasSym = true
		}
	}
	count := 0
	for _, ok := range []bool{hasDigit, hasSym, hasUpper, hasLower} {
		if ok {
			count++
		}
	}
	if count < 3 {
		return fmt.Errorf("password (%s) does not meet specifications", password)
	}
	return nil
}
