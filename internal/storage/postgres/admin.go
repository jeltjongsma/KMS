package postgres

import (
	"database/sql"
	"kms/internal/clients"
)

type PostgresAdminRepo struct {
	db *sql.DB
}

func NewPostgresAdminRepo(db *sql.DB) *PostgresAdminRepo {
	return &PostgresAdminRepo{db: db}
}

func (r *PostgresAdminRepo) GetAdmin(id int) (*clients.Client, error) {
	query := "SELECT * FROM clients WHERE id = $1"
	var client clients.Client
	err := r.db.QueryRow(query, id).Scan(&client.ID, &client.Clientname, &client.Password, &client.Role)
	return &client, err
}
