package postgres

import (
	"database/sql"
	"kms/internal/users"
)

type PostgresAdminRepo struct {
	db *sql.DB
}

func NewPostgresAdminRepo(db *sql.DB) *PostgresAdminRepo {
	return &PostgresAdminRepo{db: db}
}

func (r *PostgresAdminRepo) GetAdmin(id int) (*users.User, error) {
	query := "SELECT * FROM users WHERE id = $1"
	var user users.User 
	err := r.db.QueryRow(query, id).Scan(&user.ID, &user.Username, &user.Password, &user.Role)
	return &user, err
}