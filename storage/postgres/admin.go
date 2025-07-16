package postgres

import (
	"database/sql"
	"kms/storage"
)

type PostgresAdminRepo struct {
	db *sql.DB
}

func NewPostgresAdminRepo(db *sql.DB) *PostgresAdminRepo {
	return &PostgresAdminRepo{db: db}
}

func (r *PostgresAdminRepo) GetAdmin(id int) (storage.User, error) {
	query := "SELECT * FROM users WHERE id = $1"
	var user storage.User 
	err := r.db.QueryRow(query, id).Scan(&user.ID, &user.Email, &user.Password, &user.Role)
	return user, err
}