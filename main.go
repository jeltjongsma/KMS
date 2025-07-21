package main

import (
	"net/http"
	"log"
	"kms/server"
	"kms/storage/postgres"
	"kms/infra"
	"fmt"
	b64 "encoding/base64"
) 

func main() {
	cfg, err := infra.LoadConfig(".env")
	if err != nil {
		log.Fatal("Unable to load config: ", err)
	}
	jwtSecret, err := b64.RawURLEncoding.DecodeString(cfg["JWT_SECRET"])
	if err != nil {
		log.Fatal("Unable to decode JWT secret: ", err)
	}
	KEK, err := b64.RawURLEncoding.DecodeString(cfg["KEK"])
	if err != nil {
		log.Fatal("Unable to decode KEK: ", err)
	}
	keyRefSecret, err := b64.RawURLEncoding.DecodeString(cfg["KEY_REF_SECRET"])
	if err != nil {
		log.Fatal("Unable to decode keyRefSecret: ", err)
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
				"keyReference": "TEXT",
				"dek": 	"TEXT",
				"userId": "INT",
				"encoding": "TEXT",
			},
			Keys: []string{
				"id",
				"keyReference",
				"dek",
				"userId",
				"encoding",
			},
			Unique: []string{"userId", "keyReference"},
		},
		postgres.TableSchema{
			Name: "users",
			Fields: map[string]string{
				"id": 	"SERIAL PRIMARY KEY",
				"email": "TEXT UNIQUE NOT NULL",
				"password": "TEXT NOT NULL",
				"role": "TEXT NOT NULL DEFAULT 'user'",
			},
			Keys: []string{
				"id",
				"email",
				"password",
				"role",
			},
		},
	}

	if err := postgres.InitSchema(cfg, db, schemas, KEK); err != nil {
		log.Fatal("Failed to create schema: ", err)
	}



	appCtx := &infra.AppContext{
		Cfg: cfg,
		JWTSecret: jwtSecret,
		KEK: KEK,
		KeyRefSecret: keyRefSecret,
		DB: db,
	}

	server.RegisterRoutes(appCtx)

	http.ListenAndServe(fmt.Sprintf(":%v", cfg["SERVER_PORT"]), nil)
}