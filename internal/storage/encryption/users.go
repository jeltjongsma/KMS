package encryption

import (
	c "kms/internal/bootstrap/context"
	"kms/internal/clients"
)

type EncryptedClientRepo struct {
	ClientRepo clients.ClientRepository
	KeyManager c.KeyManager
}

func NewEncryptedClientRepo(clientRepo clients.ClientRepository, keyManager c.KeyManager) *EncryptedClientRepo {
	return &EncryptedClientRepo{
		ClientRepo: clientRepo,
		KeyManager: keyManager,
	}
}

func (r *EncryptedClientRepo) CreateClient(client *clients.Client) (int, error) {
	encClient := &clients.Client{}
	if err := EncryptFields(encClient, client, r.KeyManager); err != nil {
		return 0, err
	}
	id, err := r.ClientRepo.CreateClient(encClient)
	if err != nil {
		return 0, err
	}
	return id, nil
}

func (r *EncryptedClientRepo) GetClient(id int) (*clients.Client, error) {
	client, err := r.ClientRepo.GetClient(id)
	if err != nil {
		return nil, err
	}
	decClient := &clients.Client{}
	if err := DecryptFields(decClient, client, r.KeyManager); err != nil {
		return nil, err
	}
	return decClient, nil
}

func (r *EncryptedClientRepo) GetAll() ([]clients.Client, error) {
	stored, err := r.ClientRepo.GetAll()
	if err != nil {
		return nil, err
	}

	decClients := make([]clients.Client, len(stored))
	for idx, u := range stored {
		decU := &clients.Client{}
		if err := DecryptFields(decU, &u, r.KeyManager); err != nil {
			return nil, err
		}
		decClients[idx] = *decU
	}

	return decClients, nil
}

func (r *EncryptedClientRepo) Delete(clientId int) error {
	return r.ClientRepo.Delete(clientId)
}

func (r *EncryptedClientRepo) FindByHashedClientname(email string) (*clients.Client, error) {
	client, err := r.ClientRepo.FindByHashedClientname(email)
	if err != nil {
		return nil, err
	}
	decClient := &clients.Client{}
	if err := DecryptFields(decClient, client, r.KeyManager); err != nil {
		return nil, err
	}
	return decClient, nil
}

func (r *EncryptedClientRepo) UpdateRole(id int, role string) error {
	encRole, err := EncryptString(role, r.KeyManager.DBKey())
	if err != nil {
		return err
	}
	return r.ClientRepo.UpdateRole(id, encRole)
}

func (r *EncryptedClientRepo) GetRole(id int) (string, error) {
	encRole, err := r.ClientRepo.GetRole(id)
	if err != nil {
		return "", err
	}
	role, err := DecryptString(encRole, r.KeyManager.DBKey())
	if err != nil {
		return "", err
	}
	return role, nil
}
