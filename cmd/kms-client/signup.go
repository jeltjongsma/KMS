package main

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"kms/internal/auth"
	"kms/internal/bootstrap"
	"kms/pkg/cli"
	"net/http"
	"os"
	"time"
)

func runSignup(args []string) {
	fs := flag.NewFlagSet("signup", flag.ExitOnError)
	var (
		token string
	)
	fs.StringVar(&token, "token", "", "signup token")
	fs.Parse(args)

	if token == "" {
		fmt.Fprintln(os.Stderr, "error: --token is required")
		usage()
		os.Exit(2)
	}

	// read password
	password, err := cli.RequirePasswordTwice()
	cli.HandleUnexpectedError(err)

	cred := &auth.SignupCredentials{
		Token:    token,
		Password: password,
	}

	cfg, err := bootstrap.LoadConfig(".env")
	cli.HandleUnexpectedError(err)

	// signup
	body, err := json.Marshal(cred)
	cli.HandleUnexpectedError(err)

	req, err := http.NewRequest("POST", fmt.Sprintf("https://%s:%s/auth/signup", cfg["SERVER_HOST"], cfg["SERVER_PORT"]), bytes.NewReader(body))
	cli.HandleUnexpectedError(err)

	req.Header.Set("Content-Type", "application/json")

	// allow self-signed cert in dev mode
	tlsCfg := &tls.Config{MinVersion: tls.VersionTLS12}
	if cfg["ENV"] == "dev" {
		tlsCfg.InsecureSkipVerify = true
	}

	client := &http.Client{
		Timeout: 15 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: tlsCfg,
		},
	}

	resp, err := client.Do(req)
	cli.HandleFailedRequest(err)

	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		if len(bytes.TrimSpace(body)) == 0 {
			body = []byte(resp.Status) // fallback if no body
		}
		fmt.Fprintf(os.Stderr, "server error (%d): %s\n", resp.StatusCode, body)
		os.Exit(1)
	}

	fmt.Printf("Signup successful, status code: %d\n", resp.StatusCode)
}
