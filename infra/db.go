package infra 

import (
	"database/sql"
	_ "github.com/lib/pq"
	"log"
	"fmt"
)

// Pass config in the future
func ConnectDatabase(port int, user string, password string) (*sql.DB, error) {
	connStr := fmt.Sprintf("port=%v user=%v password=%v dbname=postgres sslmode=disable", port, user, password)
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