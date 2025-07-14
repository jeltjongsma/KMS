package main

import (
	"net/http"
	"database/sql"
	_ "github.com/lib/pq"
	"log"
	"kms/server"
	"kms/storage/postgres"
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
// TODO: Move all of this into a better place and make functions for altering tables
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

	_, err = db.Exec(`DROP TABLE keys`)
	if err != nil {log.Fatal("Failed to drop table keys: ", err)}
	_, err = db.Exec(`DROP TABLE users`)
	if err != nil {log.Fatal("Failed to drop table users: ", err)}

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

	_, err = db.Exec(`
		CREATE TABLE users (
			id 			SERIAL PRIMARY KEY,
			email 		TEXT UNIQUE,
			fname		TEXT,
			lname		TEXT,
			password	TEXT
		)
	`)
	if err != nil {
		log.Fatal("Create table users failed: ", err)
	}

	log.Println("Connected!")

	keyRepo := postgres.NewPostgresKeyRepo(db)
	userRepo := postgres.NewPostgresUserRepo(db)
	

	server.RegisterRoutes(keyRepo, userRepo)

	http.ListenAndServe(":8080", nil)
}