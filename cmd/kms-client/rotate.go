package main

import (
	"bytes"
	"crypto/tls"
	"flag"
	"fmt"
	"io"
	"kms/internal/bootstrap"
	"kms/pkg/cli"
	"net/http"
	"os"
	"time"
)

func runRotate(args []string) {
	fs := flag.NewFlagSet("rotate", flag.ExitOnError)
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
	cli.HandleUnexpectedError(err)

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

	// rotate key
	req, err := http.NewRequest("POST", fmt.Sprintf("https://%s:%s/keys/%s/actions/rotate", cfg["SERVER_HOST"], cfg["SERVER_PORT"], ref), nil)
	cli.HandleUnexpectedError(err)

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

	fmt.Printf("Key with reference '%s' rotated successfully\n", ref)
}
