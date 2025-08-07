package admin

import (
	"fmt"
	"kms/internal/auth"
	c "kms/internal/bootstrap/context"
	"kms/internal/users"
	kmsErrors "kms/pkg/errors"
	"unicode"
)

type Service struct {
	AdminRepo  AdminRepository
	UserRepo   users.UserRepository
	KeyManager c.KeyManager
	Logger     c.Logger
}

func NewService(adminRepo AdminRepository, userRepo users.UserRepository, keyManager c.KeyManager, logger c.Logger) *Service {
	return &Service{
		AdminRepo:  adminRepo,
		UserRepo:   userRepo,
		KeyManager: keyManager,
		Logger:     logger,
	}
}

type AdminRepository interface {
	GetAdmin(id int) (*users.User, error)
}

func (s *Service) UpdateRole(userId int, role string, adminId string) *kmsErrors.AppError {
	oldRole, err := s.UserRepo.GetRole(userId)
	if err != nil {
		return kmsErrors.MapRepoErr(err)
	}

	if err := s.UserRepo.UpdateRole(userId, role); err != nil {
		return kmsErrors.MapRepoErr(err)
	}

	s.Logger.Info("User role updated", "userId", userId, "oldRole", oldRole, "newRole", role)

	return nil
}

func (s *Service) Me(userId int) (*users.User, *kmsErrors.AppError) {
	admin, err := s.UserRepo.GetUser(userId)
	if err != nil {
		return nil, kmsErrors.MapRepoErr(err)
	}
	return admin, nil
}

func (s *Service) GenerateSignupToken(body *GenerateSignupTokenRequest, adminId string) (string, *kmsErrors.AppError) {
	if err := validateUsername(body.Username); err != nil {
		return "", kmsErrors.NewAppError(
			kmsErrors.WrapError(err, map[string]any{
				"username": body.Username,
			}),
			"Username does not meet minimum requirements. 4 <= len <= 64 & [a-Z0-9\\-]",
			400,
		)
	}

	tokenGenInfo := &auth.TokenGenInfo{
		Ttl:    body.Ttl,
		Secret: s.KeyManager.SignupKey(),
		Typ:    "signup",
	}

	token, err := auth.GenerateSignupToken(tokenGenInfo, body.Username)
	if err != nil {
		return "", kmsErrors.NewInternalServerError(err)
	}

	s.Logger.Info("Generated signup token", "adminId", adminId, "username", body.Username)

	return token, nil
}

func (s *Service) GetUsers() ([]users.User, *kmsErrors.AppError) {
	users, err := s.UserRepo.GetAll()
	if err != nil {
		return nil, kmsErrors.MapRepoErr(err)
	}

	return users, nil
}

func (s *Service) DeleteUser(userId int) *kmsErrors.AppError {
	if err := s.UserRepo.Delete(userId); err != nil {
		return kmsErrors.MapRepoErr(err)
	}

	return nil
}

// Allow 0-9, a-Z and '-' in username
func validateUsername(username string) error {
	if len(username) < 4 || len(username) > 64 {
		return fmt.Errorf("username length should be between 4 and 64, is %d", len(username))
	}
	for _, r := range username {
		if !(unicode.IsLetter(r) || unicode.IsDigit(r) || r == '-') {
			return fmt.Errorf("invalid character in username (%v): %c", username, r)
		}
	}
	return nil
}
