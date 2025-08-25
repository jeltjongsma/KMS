package main

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"kms/internal/bootstrap"
	"kms/internal/keys"
	"kms/pkg/cli"
	"net/http"
	"os"
	"time"
)

func runGenerate(args []string) {
	fs := flag.NewFlagSet("generate", flag.ExitOnError)
	var (
		ref string
	)
	fs.StringVar(&ref, "ref", "", "key reference")
	fs.Parse(args)

	if ref == "" {
		fmt.Fprintln(os.Stderr, "error: --ref is required")
		usage()
		os.Exit(2)
	}

	// load config
	cfg, err := bootstrap.LoadConfig(".env")
	if err != nil {
		cli.HandleUnexpectedError(err)
	}

	// allow self-signed cert in dev mode
	tlsCfg := &tls.Config{MinVersion: tls.VersionTLS12}
	if cfg["ENV"] == "dev" {
		tlsCfg.InsecureSkipVerify = true
	}

	tr := &http.Transport{
		TLSClientConfig: tlsCfg,
	}

	client := &http.Client{
		Timeout:   15 * time.Second,
		Transport: tr,
	}

	// login
	token, err := login(cfg, client)
	cli.HandleUnexpectedError(err)

	// generate key
	generateRequest := &keys.GenerateKeyRequest{
		KeyReference: ref,
	}

	generateBody, err := json.Marshal(generateRequest)
	cli.HandleUnexpectedError(err)

	req, err := http.NewRequest("POST", fmt.Sprintf("https://%s:%s/keys/actions/generate", cfg["SERVER_HOST"], cfg["SERVER_PORT"]), bytes.NewReader(generateBody))
	cli.HandleUnexpectedError(err)

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)

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

	fmt.Printf("Key with reference '%s' generated successfully\n", ref)
}
