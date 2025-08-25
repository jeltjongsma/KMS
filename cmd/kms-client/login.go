package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"kms/internal/api/dto"
	"kms/internal/auth"
	"kms/pkg/cli"
	"net/http"
)

func login(cfg map[string]string, client *http.Client) (string, error) {
	user, err := cli.RequireName()
	if err != nil {
		cli.HandleUnexpectedError(err)
	}

	password, err := cli.RequirePassword()
	if err != nil {
		cli.HandleUnexpectedError(err)
	}

	cred := &auth.Credentials{
		Clientname: user,
		Password:   password,
	}

	loginBody, err := json.Marshal(cred)
	if err != nil {
		return "", err
	}

	req, err := http.NewRequest("POST", fmt.Sprintf("https://%s:%s/auth/login", cfg["SERVER_HOST"], cfg["SERVER_PORT"]), bytes.NewReader(loginBody))
	if err != nil {
		return "", err
	}

	req.Header.Set("Content-Type", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
		return "", fmt.Errorf("login failed: %s", body)
	}

	var respData dto.TokenResponse
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&respData); err != nil {
		return "", err
	}

	return respData.Token, nil
}
