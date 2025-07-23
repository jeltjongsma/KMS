package bootstrap 

import (
	"database/sql"
	_ "github.com/lib/pq"
	"log"
	"fmt"
	c "kms/internal/bootstrap/context"
)

func ConnectDatabase(cfg c.KmsConfig) (*sql.DB, error) {
	connStr := fmt.Sprintf("port=%v user=%v password=%v dbname=%v sslmode=%v", 
			cfg["DB_PORT"], cfg["DB_USER"], cfg["DB_PASSWORD"], cfg["DB_NAME"], cfg["DB_SSLMODE"])
	db, err := sql.Open("postgres", connStr)
	if err != nil {
		return db, err
	}
	
	if err := db.Ping(); err != nil {
		return db, err
	}

	log.Println("Succesfully connected to database")
	return db, nil
}