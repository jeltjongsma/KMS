package postgres 

import (
	"fmt"
	"database/sql"
	"strings"
	"log"
	"kms/utils/hashing"
	"kms/infra"
	"kms/storage/db_encryption"
)

type TableSchema struct {
	Name	string 
	Fields 	map[string]string
	Keys 	[]string
	Unique 	[]string
}

func createTable(db *sql.DB, schema *TableSchema) error {
	var builder strings.Builder
	stdStr := fmt.Sprintf("CREATE TABLE IF NOT EXISTS %v (", schema.Name)
	builder.WriteString(stdStr)

	for idx, key := range schema.Keys {
		column := fmt.Sprintf("%v %v", key, schema.Fields[key])
		builder.WriteString(column)
		if idx < len(schema.Keys) - 1 {
			builder.WriteString(",")
		}
	}

	if schema.Unique != nil {
		builder.WriteString(",UNIQUE (")
		for idx, key := range schema.Unique {
			builder.WriteString(key)
			if idx < len(schema.Unique) - 1 {
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

func ensureMasterAdmin(cfg infra.KmsConfig, db *sql.DB, key []byte) error {
	var count int 
	err := db.QueryRow("SELECT COUNT(*) FROM users WHERE role = 'admin'").Scan(&count)
	if err != nil {return err}

	if count == 0 {
		hashedPw, err := hashing.HashPassword(cfg["MASTER_ADMIN_PASSWORD"])
		if err != nil {return err}
		encryptedAdmin, err := db_encryption.EncryptString("admin", key)
		if err != nil {return err}
		_, err = db.Exec(
			"INSERT INTO users (email, password, role) VALUES ($1, $2, $3)", 
			cfg["MASTER_ADMIN_EMAIL"],
			hashedPw,
			encryptedAdmin,
		)
		return err
	}
	return nil
} 

func InitSchema(cfg infra.KmsConfig, db *sql.DB, schemas []TableSchema, key []byte) error {
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
		if err := ensureMasterAdmin(cfg, db, key); err != nil {return err}
	}
	return nil
}