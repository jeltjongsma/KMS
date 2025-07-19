package postgres

import (
	"database/sql"
	"kms/storage"
)

type PostgresKeyRepo struct {
	db *sql.DB
}

func NewPostgresKeyRepo(db *sql.DB) *PostgresKeyRepo {
	return &PostgresKeyRepo{db: db}
}

// TODO: Replace queries with query builder
func (r *PostgresKeyRepo) CreateKey(key *storage.Key) (*storage.Key, error) {
	query := "INSERT INTO keys (keyReference, dek, userId, encoding) VALUES ($1, $2, $3, $4) RETURNING *"
	var newKey storage.Key
	err := r.db.QueryRow(query, key.KeyReference, key.DEK, key.UserId, key.Encoding).
		Scan(&newKey.ID, &newKey.KeyReference, &newKey.DEK, &newKey.UserId, &newKey.Encoding)
	return &newKey, err
}

func (r *PostgresKeyRepo) GetKey(userId int, keyReference string) (*storage.Key, error) {
	query := "SELECT * FROM keys WHERE userId = $1 AND keyReference = $2"
	var key storage.Key
	err := r.db.QueryRow(query, userId, keyReference).
		Scan(&key.ID, &key.KeyReference, &key.DEK, &key.UserId, &key.Encoding)
	return &key, err
}

func (r *PostgresKeyRepo) GetAll() ([]storage.Key, error) {
	query := "SELECT * FROM keys"
	var keys []storage.Key
	rows, err := r.db.Query(query)
	if err != nil {return keys, err}

	defer rows.Close()
	for rows.Next() {
		var key storage.Key
		err := rows.Scan(&key.ID, &key.KeyReference, &key.DEK, &key.UserId, &key.Encoding)
		if err != nil {return keys, err}
		keys = append(keys, key)
	}
	return keys, nil
}