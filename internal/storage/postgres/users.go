package postgres

import (
	"database/sql"
	"kms/internal/users"
	kmsErrors "kms/pkg/errors"
)

type PostgresUserRepo struct {
	db *sql.DB
}

func NewPostgresUserRepo(db *sql.DB) *PostgresUserRepo {
	return &PostgresUserRepo{db: db}
}

func (r *PostgresUserRepo) CreateUser(user *users.User) (int, error) {
	query := "INSERT INTO users (username, hashedUsername, password, role) VALUES ($1, $2, $3, $4) RETURNING id"
	var id int
	err := r.db.QueryRow(query, user.Username, user.HashedUsername, user.Password, user.Role).Scan(&id)
	return id, err
}

func (r *PostgresUserRepo) GetUser(id int) (*users.User, error) {
	query := "SELECT * FROM users WHERE id = $1"
	var user users.User
	err := r.db.QueryRow(query, id).Scan(&user.ID, &user.Username, &user.HashedUsername, &user.Password, &user.Role)
	return &user, err
}

func (r *PostgresUserRepo) GetAll() ([]users.User, error) {
	query := "SELECT * FROM users"
	var allUsers []users.User
	rows, err := r.db.Query(query)
	if err != nil {
		return allUsers, err
	}
	defer rows.Close()
	for rows.Next() {
		var user users.User
		err := rows.Scan(&user.ID, &user.Username, &user.HashedUsername, &user.Password, &user.Role)
		if err != nil {
			return allUsers, err
		}
		allUsers = append(allUsers, user)
	}
	return allUsers, nil
}

func (r *PostgresUserRepo) FindByHashedUsername(email string) (*users.User, error) {
	query := "SELECT * FROM users WHERE hashedUsername = $1"
	var user users.User
	err := r.db.QueryRow(query, email).Scan(&user.ID, &user.Username, &user.HashedUsername, &user.Password, &user.Role)
	return &user, err
}

func (r *PostgresUserRepo) UpdateRole(id int, role string) error {
	query := "UPDATE users SET role = $1 WHERE id = $2"
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

func (r *PostgresUserRepo) GetRole(id int) (string, error) {
	query := "SELECT role FROM users WHERE id = $1"
	var role string
	err := r.db.QueryRow(query, id).Scan(&role)
	return role, err
}
