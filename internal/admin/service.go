package admin

import (
	"fmt"
	"kms/internal/auth"
	c "kms/internal/bootstrap/context"
	"kms/internal/clients"
	kmsErrors "kms/pkg/errors"
	"unicode"
)

type Service struct {
	AdminRepo  AdminRepository
	ClientRepo clients.ClientRepository
	KeyManager c.KeyManager
	Logger     c.Logger
}

func NewService(adminRepo AdminRepository, clientRepo clients.ClientRepository, keyManager c.KeyManager, logger c.Logger) *Service {
	return &Service{
		AdminRepo:  adminRepo,
		ClientRepo: clientRepo,
		KeyManager: keyManager,
		Logger:     logger,
	}
}

type AdminRepository interface {
	GetAdmin(id int) (*clients.Client, error)
}

func (s *Service) UpdateRole(clientId int, role string, adminId string) *kmsErrors.AppError {
	oldRole, err := s.ClientRepo.GetRole(clientId)
	if err != nil {
		return kmsErrors.MapRepoErr(err)
	}

	if err := s.ClientRepo.UpdateRole(clientId, role); err != nil {
		return kmsErrors.MapRepoErr(err)
	}

	s.Logger.Info("Client role updated", "clientId", clientId, "oldRole", oldRole, "newRole", role)

	return nil
}

func (s *Service) Me(clientId int) (*clients.Client, *kmsErrors.AppError) {
	admin, err := s.ClientRepo.GetClient(clientId)
	if err != nil {
		return nil, kmsErrors.MapRepoErr(err)
	}
	return admin, nil
}

func (s *Service) GenerateSignupToken(body *GenerateSignupTokenRequest, adminId string) (string, *kmsErrors.AppError) {
	if err := ValidateClientname(body.Clientname); err != nil {
		return "", kmsErrors.NewAppError(
			kmsErrors.WrapError(err, map[string]any{
				"clientname": body.Clientname,
			}),
			"Clientname does not meet minimum requirements. 4 <= len <= 64 & [a-Z0-9\\-]",
			400,
		)
	}

	tokenGenInfo := &auth.TokenGenInfo{
		Ttl:    body.Ttl,
		Secret: s.KeyManager.SignupKey(),
		Typ:    "signup",
	}

	token, err := auth.GenerateSignupToken(tokenGenInfo, body.Clientname)
	if err != nil {
		return "", kmsErrors.NewInternalServerError(err)
	}

	s.Logger.Info("Generated signup token", "adminId", adminId, "clientname", body.Clientname)

	return token, nil
}

func (s *Service) GetClients() ([]clients.Client, *kmsErrors.AppError) {
	clients, err := s.ClientRepo.GetAll()
	if err != nil {
		return nil, kmsErrors.MapRepoErr(err)
	}

	return clients, nil
}

func (s *Service) DeleteClient(clientId int) *kmsErrors.AppError {
	if err := s.ClientRepo.Delete(clientId); err != nil {
		return kmsErrors.MapRepoErr(err)
	}

	return nil
}

// Allow 0-9, a-Z and '-' in clientname
func ValidateClientname(clientname string) error {
	if len(clientname) < 4 || len(clientname) > 64 {
		return fmt.Errorf("clientname length should be between 4 and 64, is %d", len(clientname))
	}
	for _, r := range clientname {
		if !(unicode.IsLetter(r) || unicode.IsDigit(r) || r == '-') {
			return fmt.Errorf("invalid character in clientname (%v): %c", clientname, r)
		}
	}
	return nil
}
