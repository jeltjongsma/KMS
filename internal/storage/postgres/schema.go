package postgres

import (
	"database/sql"
	"fmt"
	c "kms/internal/bootstrap/context"
	"kms/internal/storage/encryption"
	"kms/pkg/hashing"
	"log"
	"strings"
)

type TableSchema struct {
	Name   string
	Fields map[string]string
	Keys   []string
	Unique []string
}

func createTable(db *sql.DB, schema *TableSchema) error {
	var builder strings.Builder
	stdStr := fmt.Sprintf("CREATE TABLE IF NOT EXISTS %v (", schema.Name)
	builder.WriteString(stdStr)

	for idx, key := range schema.Keys {
		column := fmt.Sprintf("%v %v", key, schema.Fields[key])
		builder.WriteString(column)
		if idx < len(schema.Keys)-1 {
			builder.WriteString(",")
		}
	}

	if schema.Unique != nil {
		builder.WriteString(",UNIQUE (")
		for idx, key := range schema.Unique {
			builder.WriteString(key)
			if idx < len(schema.Unique)-1 {
				builder.WriteString(",")
			}
		}
		builder.WriteString(")")
	}

	builder.WriteString(")")

	_, err := db.Exec(builder.String())
	return err
}

func dropTable(db *sql.DB, name string) error {
	query := fmt.Sprintf("DROP TABLE %v", name)
	_, err := db.Exec(query)
	return err
}

func ensureMasterAdmin(cfg c.KmsConfig, db *sql.DB, keyManager c.KeyManager) error {
	var count int
	// FIXME: Will always fail
	err := db.QueryRow("SELECT COUNT(*) FROM users WHERE role = 'admin'").Scan(&count)
	if err != nil {
		return err
	}

	if count == 0 {
		hashedPw, err := hashing.HashPassword(cfg["MASTER_ADMIN_PASSWORD"])
		if err != nil {
			return err
		}
		encryptedAdmin, err := encryption.EncryptString("admin", keyManager.DBKey())
		if err != nil {
			return err
		}
		encryptedUsername, err := encryption.EncryptString(cfg["MASTER_ADMIN_USERNAME"], keyManager.DBKey())
		if err != nil {
			return err
		}
		usernameSecret, err := keyManager.HashKey("username")
		if err != nil {
			return err
		}
		_, err = db.Exec(
			"INSERT INTO users (username, hashedUsername, password, role) VALUES ($1, $2, $3, $4)",
			encryptedUsername,
			hashing.HashHS256ToB64([]byte(cfg["MASTER_ADMIN_USERNAME"]), usernameSecret),
			hashedPw,
			encryptedAdmin,
		)
		return err
	}
	return nil
}

func InitSchema(cfg c.KmsConfig, db *sql.DB, schemas []TableSchema, keyManager c.KeyManager) error {
	clearTables := cfg["ENV"] == "dev" && cfg["CLEAR_DB"] == "true"
	if clearTables {
		for _, schema := range schemas {
			if err := dropTable(db, schema.Name); err != nil {
				log.Println("Failed to drop table: ", err)
			}
		}
	}
	for _, schema := range schemas {
		if err := createTable(db, &schema); err != nil {
			return err
		}
	}
	if cfg["ENV"] == "dev" {
		if err := ensureMasterAdmin(cfg, db, keyManager); err != nil {
			return err
		}
	}
	return nil
}
