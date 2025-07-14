package postgres

import (
	"database/sql"
	"kms/storage"
)

type PostgresRepo struct {
	DB *sql.DB
}

// TODO: Replace queries with query builder
func (r *PostgresRepo) CreateKey(key *storage.Key) (string, error) {
	query := "INSERT INTO keys (dek, userId) VALUES ($1, $2) RETURNING id"
	var id string
	err := r.DB.QueryRow(query, key.DEK, key.UserId).Scan(&id)
	return id, err
}

func (r *PostgresRepo) GetKey(id string) (storage.Key, error) {
	query := "SELECT * FROM keys WHERE id = $1"
	var key storage.Key
	err := r.DB.QueryRow(query, id).Scan(&key.ID, &key.DEK, &key.UserId)
	return key, err
}

func (r *PostgresRepo) GetAll() ([]storage.Key, error) {
	query := "SELECT * FROM keys"
	var keys []storage.Key
	rows, err := r.DB.Query(query)
	if err != nil {return keys, err}

	defer rows.Close()
	for rows.Next() {
		var key storage.Key
		err := rows.Scan(&key.ID, &key.DEK, &key.UserId)
		if err != nil {return keys, err}
		keys = append(keys, key)
	}
	return keys, nil
}