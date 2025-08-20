package main

import (
	"encoding/base64"
	"flag"
	"kms/internal/admin"
	"kms/internal/auth"
	"kms/internal/bootstrap"
	"log"
)

func main() {
	var (
		name string
		ttl  int64
	)

	flag.StringVar(&name, "name", "", "client's name")
	flag.Int64Var(&ttl, "ttl", 86400000, "token's time-to-live")

	flag.Parse()

	if err := admin.ValidateClientname(name); err != nil {
		log.Fatalf("invalid name: %v", err)
	}

	cfg, err := bootstrap.LoadConfig(".env")
	if err != nil {
		log.Fatalf("unexpected error: %v", err)
	}

	signupSecret, err := base64.RawURLEncoding.DecodeString(cfg["SIGNUP_SECRET"])
	if err != nil {
		log.Fatalf("unexpected error: %v", err)
	}

	genInfo := &auth.TokenGenInfo{
		Ttl:    ttl,
		Secret: signupSecret,
		Typ:    "signup",
	}

	token, err := auth.GenerateSignupToken(genInfo, name)
	if err != nil {
		log.Fatalf("unexpected error: %v", err)
	}

	log.Printf("generated signup token for '%s': %s\n", name, token)
}
