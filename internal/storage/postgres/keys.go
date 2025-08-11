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
	query := "INSERT INTO keys (keyReference, dek, clientId, encoding) VALUES ($1, $2, $3, $4) RETURNING *"
	var newKey keys.Key
	err := r.db.QueryRow(query, key.KeyReference, key.DEK, key.ClientId, key.Encoding).
		Scan(&newKey.ID, &newKey.KeyReference, &newKey.DEK, &newKey.ClientId, &newKey.Encoding)
	return &newKey, err
}

func (r *PostgresKeyRepo) GetKey(clientId int, keyReference string) (*keys.Key, error) {
	query := "SELECT * FROM keys WHERE clientId = $1 AND keyReference = $2"
	var key keys.Key
	err := r.db.QueryRow(query, clientId, keyReference).
		Scan(&key.ID, &key.KeyReference, &key.DEK, &key.ClientId, &key.Encoding)
	return &key, err
}

func (r *PostgresKeyRepo) UpdateKey(clientId int, keyReference string, newKey string) (*keys.Key, error) {
	query := "UPDATE keys SET dek = $1 WHERE clientId = $2 AND keyReference = $3 RETURNING *"
	var key keys.Key
	err := r.db.QueryRow(query, newKey, clientId, keyReference).
		Scan(&key.ID, &key.KeyReference, &key.DEK, &key.ClientId, &key.Encoding)
	return &key, err
}

func (r *PostgresKeyRepo) Delete(clientId int, keyReference string) (int, error) {
	query := "DELETE FROM keys WHERE clientId = $1 AND keyReference = $2 RETURNING id"
	var keyId int
	err := r.db.QueryRow(query, clientId, keyReference).Scan(&keyId)
	return keyId, err
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
		err := rows.Scan(&key.ID, &key.KeyReference, &key.DEK, &key.ClientId, &key.Encoding)
		if err != nil {
			return allKeys, err
		}
		allKeys = append(allKeys, key)
	}
	return allKeys, nil
}
