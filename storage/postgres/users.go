package postgres

import (
	"database/sql"
	"kms/storage"
)

type PostgresUserRepo struct {
	db * sql.DB
}

func NewPostgresUserRepo(db *sql.DB) *PostgresUserRepo {
	return &PostgresUserRepo{db: db}
}

func (r *PostgresUserRepo) CreateUser(user *storage.User) (int, error) {
	query := "INSERT INTO users (email, fname, lname, password) VALUES ($1, $2, $3, $4) RETURNING id"
	var id int
	err := r.db.QueryRow(query, user.Email, user.FName, user.LName, user.Password).Scan(&id)
	return id, err
}

func (r *PostgresUserRepo) GetUser(id int) (storage.User, error) {
	return storage.User{}, nil
}

func (r *PostgresUserRepo) GetAll() ([]storage.User, error) {
	return []storage.User{storage.User{}}, nil
}