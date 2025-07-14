package main

import (
	"net/http"
	"log"
	"kms/server"
	"kms/storage/postgres"
	"kms/infra"
	_ "github.com/lib/pq"
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
	// TODO: Replace hardcoded values with config or env 
	port := 5433
	user := "postgres"
	password := "kmsPassword"

	db, err := infra.ConnectDatabase(port, user, password)
	if err != nil {
		log.Fatal(err)
	}

	schemas := []postgres.TableSchema{
		postgres.TableSchema{
			Name: "keys",
			Fields: map[string]string{
				"id": 	"SERIAL PRIMARY KEY",
				"dek": 	"TEXT",
				"userId": "INT",
			},
			Keys: []string{
				"id",
				"dek",
				"userId",
			},
		},
		postgres.TableSchema{
			Name: "users",
			Fields: map[string]string{
				"id": 	"SERIAL PRIMARY KEY",
				"email": "TEXT UNIQUE",
				"fname": "TEXT",
				"lname": "TEXT",
				"password": "TEXT",
			},
			Keys: []string{
				"id",
				"email",
				"fname",
				"lname",
				"password",
			},
		},
	}

	if err := postgres.InitSchema(db, schemas, true); err != nil {
		log.Fatal("Failed to create schema: ", err)
	}

	keyRepo := postgres.NewPostgresKeyRepo(db)
	userRepo := postgres.NewPostgresUserRepo(db)
	

	server.RegisterRoutes(keyRepo, userRepo)

	http.ListenAndServe(":8080", nil)
}