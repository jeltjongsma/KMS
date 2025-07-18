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
func (r *PostgresKeyRepo) CreateKey(key *storage.Key) (int, error) {
	query := "INSERT INTO keys (searchableId, dek, userId, encoding) VALUES ($1, $2, $3, $4) RETURNING id"
	var id int
	err := r.db.QueryRow(query, key.SearchableId, key.DEK, key.UserId, key.Encoding).Scan(&id)
	return id, err
}

func (r *PostgresKeyRepo) GetKey(userId int, searchableId string) (storage.Key, error) {
	query := "SELECT * FROM keys WHERE userId = $1 AND searchableId = $2"
	var key storage.Key
	err := r.db.QueryRow(query, userId, searchableId).Scan(&key.ID, &key.SearchableId, &key.DEK, &key.UserId, &key.Encoding)
	return key, err
}

func (r *PostgresKeyRepo) GetAll() ([]storage.Key, error) {
	query := "SELECT * FROM keys"
	var keys []storage.Key
	rows, err := r.db.Query(query)
	if err != nil {return keys, err}

	defer rows.Close()
	for rows.Next() {
		var key storage.Key
		err := rows.Scan(&key.ID, &key.SearchableId, &key.DEK, &key.UserId, &key.Encoding)
		if err != nil {return keys, err}
		keys = append(keys, key)
	}
	return keys, nil
}