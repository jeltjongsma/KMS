package auth

import (
	"database/sql"
	"errors"
	"fmt"
	c "kms/internal/bootstrap/context"
	"kms/internal/clients"
	kmsErrors "kms/pkg/errors"
	"kms/pkg/hashing"
	"unicode"
)

type Service struct {
	Cfg          c.KmsConfig
	ClientRepo   clients.ClientRepository
	TokenGenInfo *TokenGenInfo
	KeyManager   c.KeyManager
	Logger       c.Logger
}

func NewService(
	cfg c.KmsConfig,
	clientRepo clients.ClientRepository,
	tokenGenInfo *TokenGenInfo,
	keyManager c.KeyManager,
	logger c.Logger,
) *Service {
	return &Service{
		Cfg:          cfg,
		ClientRepo:   clientRepo,
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

	clientnameSecret, err := s.KeyManager.HashKey("clientname")
	if err != nil {
		return "", kmsErrors.NewInternalServerError(err)
	}

	hashedClientname := hashing.HashHS256ToB64([]byte(token.Payload.Sub), clientnameSecret)

	s.Logger.Debug("Signup details", "clientname", token.Payload.Sub, "hashedClient", hashedClientname, "hashLength", len(hashedClientname))

	client := &clients.Client{
		Clientname:       token.Payload.Sub,
		HashedClientname: hashedClientname,
		Password:         hashedPassword,
		Role:             s.Cfg["DEFAULT_ROLE"],
	}

	id, err := s.ClientRepo.CreateClient(client)
	if err != nil {
		return "", kmsErrors.MapRepoErr(err)
	}

	client.ID = id

	jwt, err := GenerateJWT(s.TokenGenInfo, client)
	if err != nil {
		return "", kmsErrors.NewInternalServerError(err)
	}

	s.Logger.Info("Client signed up", "clientId", id)

	return jwt, nil
}

func (s *Service) Login(cred *Credentials) (string, *kmsErrors.AppError) {
	clientnameSecret, err := s.KeyManager.HashKey("clientname")
	if err != nil {
		return "", kmsErrors.NewInternalServerError(err)
	}

	hashedClientname := hashing.HashHS256ToB64([]byte(cred.Clientname), clientnameSecret)
	client, err := s.ClientRepo.FindByHashedClientname(hashedClientname)
	if err != nil {
		// Check if err is "not found" to help prevent client enumeration attacks
		if errors.Is(err, sql.ErrNoRows) {
			return "", kmsErrors.NewAppError(err, "Incorrect clientname or password", 401)
		}
		return "", kmsErrors.MapRepoErr(err)
	}

	if err := hashing.CheckPassword(client.Password, cred.Password); err != nil {
		return "", kmsErrors.MapHashErr(err)
	}

	jwt, err := GenerateJWT(s.TokenGenInfo, client)
	if err != nil {
		return "", kmsErrors.NewInternalServerError(err)
	}

	s.Logger.Info("Client signed in", "clientId", client.ID)

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
