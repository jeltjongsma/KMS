package postgres

import (
	"database/sql"
	"kms/internal/clients"
	kmsErrors "kms/pkg/errors"
)

type PostgresClientRepo struct {
	db *sql.DB
}

func NewPostgresClientRepo(db *sql.DB) *PostgresClientRepo {
	return &PostgresClientRepo{db: db}
}

func (r *PostgresClientRepo) CreateClient(client *clients.Client) (int, error) {
	query := "INSERT INTO clients (clientname, hashedClientname, password, role) VALUES ($1, $2, $3, $4) RETURNING id"
	var id int
	err := r.db.QueryRow(query, client.Clientname, client.HashedClientname, client.Password, client.Role).Scan(&id)
	return id, err
}

func (r *PostgresClientRepo) GetClient(id int) (*clients.Client, error) {
	query := "SELECT * FROM clients WHERE id = $1"
	var client clients.Client
	err := r.db.QueryRow(query, id).Scan(&client.ID, &client.Clientname, &client.HashedClientname, &client.Password, &client.Role)
	return &client, err
}

func (r *PostgresClientRepo) GetAll() ([]clients.Client, error) {
	query := "SELECT * FROM clients"
	var allClients []clients.Client
	rows, err := r.db.Query(query)
	if err != nil {
		return allClients, err
	}
	defer rows.Close()
	for rows.Next() {
		var client clients.Client
		err := rows.Scan(&client.ID, &client.Clientname, &client.HashedClientname, &client.Password, &client.Role)
		if err != nil {
			return allClients, err
		}
		allClients = append(allClients, client)
	}
	return allClients, nil
}

func (r *PostgresClientRepo) Delete(clientId int) error {
	query := "DELETE FROM clients WHERE id = $1"
	_, err := r.db.Exec(query, clientId)
	if err != nil {
		return err
	}
	return nil
}

func (r *PostgresClientRepo) FindByHashedClientname(email string) (*clients.Client, error) {
	query := "SELECT * FROM clients WHERE hashedClientname = $1"
	var client clients.Client
	err := r.db.QueryRow(query, email).Scan(&client.ID, &client.Clientname, &client.HashedClientname, &client.Password, &client.Role)
	return &client, err
}

func (r *PostgresClientRepo) UpdateRole(id int, role string) error {
	query := "UPDATE clients SET role = $1 WHERE id = $2"
	res, err := r.db.Exec(query, role, id)

	if err != nil {
		return err
	}

	nRows, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if nRows == 0 {
		return kmsErrors.WrapError(kmsErrors.ErrNoRowsAffected, map[string]interface{}{
			"id":   id,
			"role": role,
		})
	}
	return nil
}

func (r *PostgresClientRepo) GetRole(id int) (string, error) {
	query := "SELECT role FROM clients WHERE id = $1"
	var role string
	err := r.db.QueryRow(query, id).Scan(&role)
	return role, err
}
