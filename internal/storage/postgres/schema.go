package postgres

import (
	"database/sql"
	"errors"
	"kms/internal/bootstrap"
	c "kms/internal/bootstrap/context"
	"kms/internal/storage/encryption"
	"kms/pkg/hashing"

	"github.com/golang-migrate/migrate/v4"
)

func ensureMasterAdmin(cfg c.KmsConfig, db *sql.DB, keyManager c.KeyManager) error {
	var count int
	err := db.QueryRow("SELECT COUNT(*) FROM clients WHERE role = 'admin'").Scan(&count)
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
		encryptedClientname, err := encryption.EncryptString(cfg["MASTER_ADMIN_USERNAME"], keyManager.DBKey())
		if err != nil {
			return err
		}
		clientnameSecret, err := keyManager.HashKey("clientname")
		if err != nil {
			return err
		}
		_, err = db.Exec(
			"INSERT INTO clients (clientname, hashedClientname, password, role) VALUES ($1, $2, $3, $4)",
			encryptedClientname,
			hashing.HashHS256ToB64([]byte(cfg["MASTER_ADMIN_USERNAME"]), clientnameSecret),
			hashedPw,
			encryptedAdmin,
		)
		return err
	}
	return nil
}

func InitSchema(cfg c.KmsConfig, db *sql.DB, keyManager c.KeyManager, migrationsPath string) error {
	clearTables := cfg["ENV"] == "dev" && cfg["CLEAR_DB"] == "true"
	if clearTables {
		if err := bootstrap.MigrateDown(db, migrationsPath); err != nil {
			if !errors.Is(err, migrate.ErrNoChange) {
				return err
			}
		}
	}

	if err := bootstrap.MigrateUp(db, migrationsPath); err != nil {
		if !errors.Is(err, migrate.ErrNoChange) {
			return err
		}
	}
	if err := ensureMasterAdmin(cfg, db, keyManager); err != nil {
		return err
	}
	return nil
}
