package main

import (
	"net/http"
	"database/sql"
	_ "github.com/lib/pq"
	"log"
	"kms/server"
)

type Test struct {
	ID		int32 	`json:"id"`
	Name 	string	`json:"name"`
	Age		int16	`json:"age"`
}

func handleErr(err error, msg string) {
	if err != nil {
		log.Fatal(msg, err)
	}
}

func main() {

	connStr := "port=5433 user=postgres password=kmsPassword dbname=postgres sslmode=disable"

	db, err := sql.Open("postgres", connStr)
	if err != nil {
		log.Fatal("Error opening database:", err)
	}
	defer db.Close()

	err = db.Ping()
	if err != nil {
		log.Fatal("Could not reach database:", err)
	}

	_, err = db.Exec(`
		CREATE TABLE IF NOT EXISTS keys (
			id 		SERIAL PRIMARY KEY,
			dek 	TEXT,
			userid 	INT
		)
	`)
	if err != nil {
		log.Fatal("Create table failed:", err)
	}

	log.Println("Connected!")

	server.RegisterRoutes(db)

	http.ListenAndServe(":8080", nil)
}