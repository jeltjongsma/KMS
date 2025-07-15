package main

import (
	"net/http"
	"log"
	"kms/server"
	"kms/storage/postgres"
	"kms/infra"
	"fmt"
)

// TODO:
// Authentication
// Authorization
// Event log

func main() {
	cfg, err := infra.LoadConfig(".env")
	if err != nil {
		log.Fatal("Unable to load config: ", err)
	}
	
	db, err := infra.ConnectDatabase(cfg)
	if err != nil {
		log.Fatal("Unable to connect to database: ", err)
	}
	defer db.Close()

	// TODO: Implement migration instead of this mess
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
				"password": "TEXT",
			},
			Keys: []string{
				"id",
				"email",
				"password",
			},
		},
	}

	if err := postgres.InitSchema(db, schemas, true); err != nil {
		log.Fatal("Failed to create schema: ", err)
	}

	// TODO: Create AppContext for passing around repos and cfg
	keyRepo := postgres.NewPostgresKeyRepo(db)
	userRepo := postgres.NewPostgresUserRepo(db)
	
	server.RegisterRoutes(cfg, keyRepo, userRepo)

	http.ListenAndServe(fmt.Sprintf(":%v", cfg["SERVER_PORT"]), nil)
}