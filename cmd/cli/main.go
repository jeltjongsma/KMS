package main

import (
	"encoding/base64"
	"flag"
	"kms/internal/auth"
	"kms/internal/bootstrap"
	"log"
)

func main() {
	var (
		name string
		ttl  int64
	)

	flag.StringVar(&name, "name", "", "Client's name")
	flag.Int64Var(&ttl, "ttl", 86400000, "Token's time-to-live")

	flag.Parse()

	cfg, err := bootstrap.LoadConfig(".env")
	if err != nil {
		log.Fatalf("unexpected error: %v", err)
	}

	secret, err := base64.RawURLEncoding.DecodeString(cfg["SIGNUP_SECRET"])
	if err != nil {
		log.Fatalf("unexpected error: %v", err)
	}

	genInfo := &auth.TokenGenInfo{
		Ttl:    ttl,
		Secret: secret,
		Typ:    "signup",
	}

	token, err := auth.GenerateSignupToken(genInfo, name)
	if err != nil {
		log.Fatalf("unexpected error: %v", err)
	}

	log.Printf("Generated signup token for '%s': %s\n", name, token)
}
