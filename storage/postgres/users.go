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
	query := "SELECT * FROM users WHERE id = $1"
	var user storage.User
	err := r.db.QueryRow(query, id).Scan(&user.ID, &user.Email, &user.FName, &user.LName, &user.Password)
	return user, err
}

func (r *PostgresUserRepo) GetAll() ([]storage.User, error) {
	query := "SELECT * FROM users"
	var users []storage.User
	rows, err := r.db.Query(query)
	if err != nil {return users, err}
	defer rows.Close()
	for rows.Next() {
		var user storage.User
		err := rows.Scan(&user.ID, &user.Email, &user.FName, &user.LName, &user.Password)
		if err != nil {return users, err}
		users = append(users, user)
	}
	return users, nil
}