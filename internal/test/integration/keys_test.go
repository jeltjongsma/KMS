package integration

import (
	"encoding/json"
	"fmt"
	"kms/internal/test"
	"kms/pkg/hashing"
	"testing"
)

func TestGenerateKey(t *testing.T) {
	u, err := requireClient(appCtx, "keys-generatekey", "client")
	test.RequireErrNil(t, err)

	token, err := requireJWT(appCtx, u)
	test.RequireErrNil(t, err)

	keyRef := "database-key"
	resp, err := doRequest("POST", "/keys/actions/generate", fmt.Sprintf(`{"keyReference":"%s"}`, keyRef),
		"Authorization", "Bearer "+token)
	requireReqNotFailed(t, err)
	defer resp.Body.Close()

	requireStatusCode(t, resp.StatusCode, 200)

	body := GetBody(resp)
	test.RequireContains(t, body, `"dek":`)
	test.RequireContains(t, body, `"encoding":`)

	keyRefHashKey, err := appCtx.KeyManager.HashKey("keyReference")
	test.RequireErrNil(t, err)
	keyRefHash := hashing.HashHS256ToB64([]byte(keyRef), keyRefHashKey)

	// check if key was created
	key, err := appCtx.KeyRepo.GetKey(u.ID, keyRefHash)
	test.RequireErrNil(t, err)

	// check if key ref hash is correct
	if key.KeyReference != keyRefHash {
		t.Errorf("expected reference: %s, got %s", keyRefHash, key.KeyReference)
	}
	// check if client ID is correct
	if key.ClientId != u.ID {
		t.Errorf("expected clientID: %v, got %v", u.ID, key.ClientId)
	}
}

func TestGenerateKey_MissingToken(t *testing.T) {
	_, err := requireClient(appCtx, "keys-generatekey-missingtoken", "client")
	test.RequireErrNil(t, err)

	keyRef := "database-key"
	resp, err := doRequest("POST", "/keys/actions/generate", fmt.Sprintf(`{"keyReference":"%s"}`, keyRef))
	requireReqNotFailed(t, err)
	defer resp.Body.Close()

	requireUnauthorized(t, resp)
}

func TestGenerateKey_InvalidKeyReference(t *testing.T) {
	u, err := requireClient(appCtx, "keys-generatekey-invkeyref", "client")
	test.RequireErrNil(t, err)

	token, err := requireJWT(appCtx, u)
	test.RequireErrNil(t, err)

	keyRef := "database_key"
	resp, err := doRequest("POST", "/keys/actions/generate", fmt.Sprintf(`{"keyReference":"%s"}`, keyRef),
		"Authorization", "Bearer "+token)
	requireReqNotFailed(t, err)
	defer resp.Body.Close()

	requireStatusCode(t, resp.StatusCode, 400)
	test.RequireContains(t, GetBody(resp), "Key reference does not meet minimum requirements")
}

func TestGetKey(t *testing.T) {
	u, err := requireClient(appCtx, "keys-getkey", "client")
	test.RequireErrNil(t, err)

	keyRef := "db-key"
	key, err := requireKey(appCtx, u.ID, keyRef)
	test.RequireErrNil(t, err)

	token, err := requireJWT(appCtx, u)
	test.RequireErrNil(t, err)

	resp, err := doRequest("GET", "/keys/"+keyRef, "",
		"Authorization", "Bearer "+token)
	requireReqNotFailed(t, err)
	defer resp.Body.Close()

	requireStatusCode(t, resp.StatusCode, 200)

	var body map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		t.Fatalf("failed to decode response body: %v", err)
	}

	// Check if dek is correct
	dek, ok := body["dek"]
	if !ok {
		t.Fatal("missing return value: dek")
	}
	if dek != key.DEK {
		t.Errorf("expected dek: %s, got %s", key.DEK, dek)
	}

	// check if encoding is correct
	enc, ok := body["encoding"]
	if !ok {
		t.Fatal("missing return value: encoding")
	}
	if enc != key.Encoding {
		t.Errorf("expected encoding: %s, got %s", key.Encoding, enc)
	}
}

func TestGetKey_MissingToken(t *testing.T) {
	u, err := requireClient(appCtx, "keys-getkey-missingtoken", "client")
	test.RequireErrNil(t, err)

	keyRef := "db-key"
	_, err = requireKey(appCtx, u.ID, keyRef)
	test.RequireErrNil(t, err)

	resp, err := doRequest("GET", "/keys/"+keyRef, "")
	requireReqNotFailed(t, err)
	defer resp.Body.Close()

	requireUnauthorized(t, resp)
}

func TestGetKey_NotFound(t *testing.T) {
	u, err := requireClient(appCtx, "keys-getkey-notfound", "client")
	test.RequireErrNil(t, err)

	token, err := requireJWT(appCtx, u)
	test.RequireErrNil(t, err)

	resp, err := doRequest("GET", "/keys/not-found", "",
		"Authorization", "Bearer "+token)
	requireReqNotFailed(t, err)
	defer resp.Body.Close()

	requireStatusCode(t, resp.StatusCode, 404)
	test.RequireContains(t, GetBody(resp), "Entity not found")
}

func TestGetKey_InvalidKeyReference(t *testing.T) {
	u, err := requireClient(appCtx, "keys-getkey-invkeyref", "client")
	test.RequireErrNil(t, err)

	token, err := requireJWT(appCtx, u)
	test.RequireErrNil(t, err)

	resp, err := doRequest("GET", "/keys/invalid+reference", "",
		"Authorization", "Bearer "+token)
	requireReqNotFailed(t, err)
	defer resp.Body.Close()

	requireStatusCode(t, resp.StatusCode, 400)
	test.RequireContains(t, GetBody(resp), "Invalid key reference")
}

func TestRenewKey(t *testing.T) {
	u, err := requireClient(appCtx, "keys-renewkey", "client")
	test.RequireErrNil(t, err)

	keyRef := "db-key"
	key, err := requireKey(appCtx, u.ID, keyRef)
	test.RequireErrNil(t, err)

	token, err := requireJWT(appCtx, u)
	test.RequireErrNil(t, err)

	resp, err := doRequest("PATCH", "/keys/"+keyRef+"/actions/renew", "",
		"Authorization", "Bearer "+token)
	requireReqNotFailed(t, err)
	defer resp.Body.Close()

	requireStatusCode(t, resp.StatusCode, 200)

	var body map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		t.Fatalf("failed to decode response body: %v", err)
	}

	// Check if dek is correct
	dek, ok := body["dek"]
	if !ok {
		t.Fatal("missing return value: dek")
	}
	if dek == key.DEK {
		t.Errorf("expected different dek: %s, got %s", key.DEK, dek)
	}

	// check if encoding is correct
	enc, ok := body["encoding"]
	if !ok {
		t.Fatal("missing return value: encoding")
	}
	if enc != key.Encoding {
		t.Errorf("expected encoding: %s, got %s", key.Encoding, enc)
	}
}

func TestRenewKey_MissingToken(t *testing.T) {
	resp, err := doRequest("PATCH", "/keys/keyRef/actions/renew", "")
	requireReqNotFailed(t, err)
	defer resp.Body.Close()

	requireStatusCode(t, resp.StatusCode, 401)
	test.RequireContains(t, GetBody(resp), "Unauthorized")
}

func TestRenewKey_InvalidKeyReference(t *testing.T) {
	u, err := requireClient(appCtx, "keys-renewkey-invkeyref", "client")
	test.RequireErrNil(t, err)

	token, err := requireJWT(appCtx, u)
	test.RequireErrNil(t, err)

	resp, err := doRequest("PATCH", "/keys/invalid+reference/actions/renew", "",
		"Authorization", "Bearer "+token)
	requireReqNotFailed(t, err)
	defer resp.Body.Close()

	requireStatusCode(t, resp.StatusCode, 400)
	test.RequireContains(t, GetBody(resp), "Invalid key reference")
}

func TestDeleteKey(t *testing.T) {
	u, err := requireClient(appCtx, "keys-delete", "client")
	test.RequireErrNil(t, err)

	keyRef := "db-key"
	key, err := requireKey(appCtx, u.ID, keyRef)
	test.RequireErrNil(t, err)

	token, err := requireJWT(appCtx, u)
	test.RequireErrNil(t, err)

	resp, err := doRequest("DELETE", "/keys/"+keyRef+"/actions/delete", "",
		"Authorization", "Bearer "+token)
	requireReqNotFailed(t, err)
	defer resp.Body.Close()

	requireStatusCode(t, resp.StatusCode, 204)

	// check if key is actually deleted
	_, err = appCtx.KeyRepo.GetKey(u.ID, key.KeyReference)
	test.RequireErrNotNil(t, err)
	test.RequireContains(t, err.Error(), "no rows")
}

func TestDeleteKey_MissingToken(t *testing.T) {
	u, err := requireClient(appCtx, "keys-delete-missingtoken", "client")
	test.RequireErrNil(t, err)

	keyRef := "db-key"
	key, err := requireKey(appCtx, u.ID, keyRef)
	test.RequireErrNil(t, err)

	resp, err := doRequest("DELETE", "/keys/"+keyRef+"/actions/delete", "")
	requireReqNotFailed(t, err)
	defer resp.Body.Close()

	requireUnauthorized(t, resp)

	// check if key wasn't deleted regardless
	_, err = appCtx.KeyRepo.GetKey(u.ID, key.KeyReference)
	test.RequireErrNil(t, err)
}

func TestDeleteKey_InvalidReference(t *testing.T) {
	u, err := requireClient(appCtx, "keys-delete-invalidref", "client")
	test.RequireErrNil(t, err)

	token, err := requireJWT(appCtx, u)
	test.RequireErrNil(t, err)

	resp, err := doRequest("DELETE", "/keys/invalid+ref/actions/delete", "",
		"Authorization", "Bearer "+token)
	requireReqNotFailed(t, err)
	defer resp.Body.Close()

	requireStatusCode(t, resp.StatusCode, 400)
	test.RequireContains(t, GetBody(resp), "Invalid key reference")
}
