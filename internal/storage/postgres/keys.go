package postgres

import (
	"database/sql"
	"kms/internal/keys"
)

type PostgresKeyRepo struct {
	db *sql.DB
}

func NewPostgresKeyRepo(db *sql.DB) *PostgresKeyRepo {
	return &PostgresKeyRepo{db: db}
}

func (r *PostgresKeyRepo) CreateKey(key *keys.Key) (*keys.Key, error) {
	query := "INSERT INTO keys (keyReference, dek, userId, encoding) VALUES ($1, $2, $3, $4) RETURNING *"
	var newKey keys.Key
	err := r.db.QueryRow(query, key.KeyReference, key.DEK, key.UserId, key.Encoding).
		Scan(&newKey.ID, &newKey.KeyReference, &newKey.DEK, &newKey.UserId, &newKey.Encoding)
	return &newKey, err
}

func (r *PostgresKeyRepo) GetKey(userId int, keyReference string) (*keys.Key, error) {
	query := "SELECT * FROM keys WHERE userId = $1 AND keyReference = $2"
	var key keys.Key
	err := r.db.QueryRow(query, userId, keyReference).
		Scan(&key.ID, &key.KeyReference, &key.DEK, &key.UserId, &key.Encoding)
	return &key, err
}

func (r *PostgresKeyRepo) UpdateKey(userId int, keyReference string, newKey string) (*keys.Key, error) {
	query := "UPDATE keys SET dek = $1 WHERE userId = $2 AND keyReference = $3 RETURNING *"
	var key keys.Key
	err := r.db.QueryRow(query, newKey, userId, keyReference).
		Scan(&key.ID, &key.KeyReference, &key.DEK, &key.UserId, &key.Encoding)
	return &key, err
}

func (r *PostgresKeyRepo) GetAll() ([]keys.Key, error) {
	query := "SELECT * FROM keys"
	var allKeys []keys.Key
	rows, err := r.db.Query(query)
	if err != nil {
		return allKeys, err
	}

	defer rows.Close()
	for rows.Next() {
		var key keys.Key
		err := rows.Scan(&key.ID, &key.KeyReference, &key.DEK, &key.UserId, &key.Encoding)
		if err != nil {
			return allKeys, err
		}
		allKeys = append(allKeys, key)
	}
	return allKeys, nil
}
