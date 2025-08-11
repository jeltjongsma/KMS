package integration

import (
	"bytes"
	"encoding/base64"
	"errors"
	"io"
	"kms/internal/auth"
	"kms/internal/bootstrap"
	"kms/internal/clients"
	"kms/internal/keys"
	"kms/internal/test"
	"kms/pkg/encryption"
	"kms/pkg/hashing"
	"net/http"
	"strconv"
	"testing"
)

func requireReqNotFailed(t *testing.T, err error) {
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
}

func requireStatusCode(t *testing.T, got int, expected int) {
	if got != expected {
		t.Fatalf("expected status code %d, got %d", expected, got)
	}
}

func GetBody(resp *http.Response) string {
	buf := new(bytes.Buffer)
	buf.ReadFrom(resp.Body)
	return buf.String()
}

func requireJWT(appCtx *bootstrap.AppContext, u *clients.Client) (string, error) {
	ttl, _ := strconv.ParseInt(appCtx.Cfg["JWT_TTL"], 10, 64)
	genInfo := &auth.TokenGenInfo{
		Ttl:    ttl,
		Secret: appCtx.KeyManager.JWTKey(),
		Typ:    "jwt",
	}

	return auth.GenerateJWT(genInfo, u)
}

func requireSignupToken(appCtx *bootstrap.AppContext, clientname string) (string, error) {
	genInfo := &auth.TokenGenInfo{
		Ttl:    3600,
		Secret: appCtx.KeyManager.SignupKey(),
		Typ:    "signup",
	}

	return auth.GenerateSignupToken(genInfo, clientname)
}

func requireClient(appCtx *bootstrap.AppContext, clientname, role string) (*clients.Client, error) {
	clientHashKey, err := appCtx.KeyManager.HashKey("clientname")
	if err != nil {
		return nil, err
	}
	password, err := hashing.HashPassword("password")
	if err != nil {
		return nil, err
	}
	hashedClient := hashing.HashHS256ToB64([]byte(clientname), clientHashKey)
	_, err = appCtx.ClientRepo.CreateClient(&clients.Client{
		Clientname:       clientname,
		HashedClientname: hashedClient,
		Password:         password,
		Role:             role,
	})
	if err != nil {
		return nil, err
	}

	return appCtx.ClientRepo.FindByHashedClientname(hashedClient)
}

func doRequest(method, path, payload string, headers ...string) (*http.Response, error) {
	if len(headers)%2 != 0 {
		return nil, errors.New("expected even number of headers")
	}
	var arg io.Reader
	if payload != "" {
		arg = bytes.NewBufferString(payload)
	}
	req, err := http.NewRequest(method, server.URL+path, arg)
	if err != nil {
		return nil, err
	}

	for i := 0; i < len(headers); i += 2 {
		req.Header.Set(headers[i], headers[i+1])
	}

	return http.DefaultClient.Do(req)
}

func requireKey(appCtx *bootstrap.AppContext, clientID int, keyRef string) (*keys.Key, error) {
	keyRefHashKey, err := appCtx.KeyManager.HashKey("keyReference")
	if err != nil {
		return nil, err
	}
	dekBytes, err := encryption.GenerateKey(32)
	if err != nil {
		return nil, err
	}
	dek := base64.RawURLEncoding.EncodeToString(dekBytes)
	return appCtx.KeyRepo.CreateKey(&keys.Key{
		KeyReference: hashing.HashHS256ToB64([]byte(keyRef), keyRefHashKey),
		DEK:          dek,
		ClientId:     clientID,
		Encoding:     "encoding",
	})
}

func requireUnauthorized(t *testing.T, r *http.Response) {
	requireStatusCode(t, r.StatusCode, 401)
	test.RequireContains(t, GetBody(r), "Unauthorized")
}

func requireBadRequest(t *testing.T, r *http.Response) {
	requireStatusCode(t, r.StatusCode, 400)
	test.RequireContains(t, GetBody(r), "Invalid request body")
}

func requireForbidden(t *testing.T, r *http.Response) {
	requireStatusCode(t, r.StatusCode, 403)
	test.RequireContains(t, GetBody(r), "Forbidden")
}
