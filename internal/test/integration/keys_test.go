package integration

import (
	"encoding/json"
	"fmt"
	"kms/internal/keys"
	"kms/internal/test"
	"kms/pkg/hashing"
	"strconv"
	"testing"
	"time"
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
	test.RequireContains(t, body, `"version":`)
	test.RequireContains(t, body, `"encoding":`)

	keyRefHashKey, err := appCtx.KeyManager.HashKey("keyReference")
	test.RequireErrNil(t, err)
	keyRefHash := hashing.HashHS256ToB64([]byte(keyRef), keyRefHashKey)

	// check if key was created
	key, err := appCtx.KeyRepo.GetKey(u.ID, keyRefHash, 1)
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
	key, err := requireKey(appCtx, u.ID, keyRef, 1, keys.StateDeprecated)
	test.RequireErrNil(t, err)

	token, err := requireJWT(appCtx, u)
	test.RequireErrNil(t, err)

	resp, err := doRequest("GET", "/keys/"+keyRef+"/"+strconv.Itoa(key.Version), "",
		"Authorization", "Bearer "+token)
	requireReqNotFailed(t, err)
	defer resp.Body.Close()

	requireStatusCode(t, resp.StatusCode, 200)
	requireHeader(t, &resp.Header, "X-Key-Deprecated", "false")

	var body keys.KeyLookupResponse
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		t.Fatalf("failed to decode response body: %v", err)
	}

	// check if decrypt is correct
	decryptW := body.DecryptWith
	if decryptW == nil {
		t.Fatal("expected decryptWith, got nil")
	}
	if decryptW.DEK != key.DEK || decryptW.Version != key.Version || decryptW.Encoding != key.Encoding {
		t.Errorf("expected %v, got %v", key, decryptW)
	}
	before := time.Now().Add(time.Minute * 5)
	if decryptW.ExpiresAt.After(before) {
		t.Errorf("expected expiresAt to be before %v, got %v", before, decryptW.ExpiresAt)
	}

	// check if encrypt is correct
	encryptW := body.EncryptWith
	if encryptW == nil {
		t.Fatal("expected decryptWith, got nil")
	}
	if encryptW.DEK != key.DEK || encryptW.Version != key.Version || encryptW.Encoding != key.Encoding {
		t.Errorf("expected %v, got %v", key, encryptW)
	}
	before = time.Now().Add(time.Minute * 5)
	if encryptW.ExpiresAt.After(before) {
		t.Errorf("expected expiresAt to be before %v, got %v", before, encryptW.ExpiresAt)
	}
}

func TestGetKey_Deprecated(t *testing.T) {
	u, err := requireClient(appCtx, "keys-getkey-deprecated", "client")
	test.RequireErrNil(t, err)

	keyRef := "db-key"
	key, err := requireKey(appCtx, u.ID, keyRef, 1, keys.StateDeprecated)
	test.RequireErrNil(t, err)
	latestKey, err := requireKey(appCtx, u.ID, keyRef, 2, keys.StateInUse)
	test.RequireErrNil(t, err)

	token, err := requireJWT(appCtx, u)
	test.RequireErrNil(t, err)

	resp, err := doRequest("GET", "/keys/"+keyRef+"/"+strconv.Itoa(key.Version), "",
		"Authorization", "Bearer "+token)
	requireReqNotFailed(t, err)
	defer resp.Body.Close()

	requireStatusCode(t, resp.StatusCode, 200)
	requireHeader(t, &resp.Header, "X-Key-Deprecated", "true")

	var body keys.KeyLookupResponse
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		t.Fatalf("failed to decode response body: %v", err)
	}

	// check if decrypt is correct
	decryptW := body.DecryptWith
	if decryptW == nil {
		t.Fatal("expected decryptWith, got nil")
	}
	if decryptW.DEK != key.DEK || decryptW.Version != key.Version || decryptW.Encoding != key.Encoding {
		t.Errorf("expected %v, got %v", key, decryptW)
	}
	before := time.Now().Add(time.Minute * 5)
	if decryptW.ExpiresAt.After(before) {
		t.Errorf("expected expiresAt to be before %v, got %v", before, decryptW.ExpiresAt)
	}

	// check if encrypt is correct
	encryptW := body.EncryptWith
	if encryptW == nil {
		t.Fatal("expected decryptWith, got nil")
	}
	if encryptW.DEK != latestKey.DEK || encryptW.Version != latestKey.Version || encryptW.Encoding != latestKey.Encoding {
		t.Errorf("expected %v, got %v", key, encryptW)
	}
	before = time.Now().Add(time.Minute * 5)
	if encryptW.ExpiresAt.After(before) {
		t.Errorf("expected expiresAt to be before %v, got %v", before, encryptW.ExpiresAt)
	}
}

func TestGetKey_MissingToken(t *testing.T) {
	u, err := requireClient(appCtx, "keys-getkey-missingtoken", "client")
	test.RequireErrNil(t, err)

	keyRef := "db-key"
	key, err := requireKey(appCtx, u.ID, keyRef, 1, "state")
	test.RequireErrNil(t, err)

	resp, err := doRequest("GET", "/keys/"+keyRef+"/"+strconv.Itoa(key.Version), "")
	requireReqNotFailed(t, err)
	defer resp.Body.Close()

	requireUnauthorized(t, resp)
}

func TestGetKey_NotFound(t *testing.T) {
	u, err := requireClient(appCtx, "keys-getkey-notfound", "client")
	test.RequireErrNil(t, err)

	token, err := requireJWT(appCtx, u)
	test.RequireErrNil(t, err)

	resp, err := doRequest("GET", "/keys/not-found/1", "",
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

	resp, err := doRequest("GET", "/keys/invalid+reference/1", "",
		"Authorization", "Bearer "+token)
	requireReqNotFailed(t, err)
	defer resp.Body.Close()

	requireStatusCode(t, resp.StatusCode, 400)
	test.RequireContains(t, GetBody(resp), "Invalid key reference")
}

func TestRotateKey(t *testing.T) {
	u, err := requireClient(appCtx, "keys-rotatekey", "client")
	test.RequireErrNil(t, err)

	keyRef := "db-key"
	key, err := requireKey(appCtx, u.ID, keyRef, 1, keys.StateInUse)
	test.RequireErrNil(t, err)

	token, err := requireJWT(appCtx, u)
	test.RequireErrNil(t, err)

	resp, err := doRequest("POST", "/keys/"+keyRef+"/actions/rotate", "",
		"Authorization", "Bearer "+token)
	requireReqNotFailed(t, err)
	defer resp.Body.Close()

	requireStatusCode(t, resp.StatusCode, 200)

	var body keys.KeyResponse
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		t.Fatalf("failed to decode response body: %v", err)
	}

	if body.Encoding != "base64url (RFC 4648)" {
		t.Errorf("expected 'base64url (RFC 4648), got %s", body.Encoding)
	}

	if body.DEK == key.DEK {
		t.Errorf("expected DEKs to be different, got %s == %s", key.DEK, body.DEK)
	}

	stored, err := appCtx.KeyRepo.GetLatestKey(key.ClientId, key.KeyReference)
	test.RequireErrNil(t, err)

	// check if fields that should stay the same, stayed the same
	if key.ClientId != stored.ClientId || key.KeyReference != stored.KeyReference {
		t.Errorf("expected clientId = %d and keyRef = %s, got %d and %s", key.ClientId, key.KeyReference, stored.ClientId, stored.KeyReference)
	}

	original, err := appCtx.KeyRepo.GetKey(key.ClientId, key.KeyReference, 1)
	test.RequireErrNil(t, err)

	// check if original's state has been set to 'deprecated'
	if original.State != keys.StateDeprecated {
		t.Errorf("expected original's state %s, got %s", keys.StateDeprecated, original.State)
	}
}

func TestRotateKey_MissingToken(t *testing.T) {
	resp, err := doRequest("POST", "/keys/keyRef/actions/rotate", "")
	requireReqNotFailed(t, err)
	defer resp.Body.Close()

	requireStatusCode(t, resp.StatusCode, 401)
	test.RequireContains(t, GetBody(resp), "Unauthorized")
}

func TestRotateKey_InvalidKeyReference(t *testing.T) {
	u, err := requireClient(appCtx, "keys-rotatekey-invkeyref", "client")
	test.RequireErrNil(t, err)

	token, err := requireJWT(appCtx, u)
	test.RequireErrNil(t, err)

	resp, err := doRequest("POST", "/keys/invalid+reference/actions/rotate", "",
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
	_, err = requireKey(appCtx, u.ID, keyRef, 1, keys.StateDeprecated)
	test.RequireErrNil(t, err)
	_, err = requireKey(appCtx, u.ID, keyRef, 2, keys.StateInUse)
	test.RequireErrNil(t, err)

	token, err := requireJWT(appCtx, u)
	test.RequireErrNil(t, err)

	resp, err := doRequest("DELETE", "/keys/"+keyRef+"/actions/delete", "",
		"Authorization", "Bearer "+token)
	requireReqNotFailed(t, err)
	defer resp.Body.Close()

	requireStatusCode(t, resp.StatusCode, 204)

	// check if all key versions are deleted
	_, err = appCtx.KeyRepo.GetKey(u.ID, keyRef, 1)
	test.RequireErrNotNil(t, err)
	test.RequireContains(t, err.Error(), "no rows")

	_, err = appCtx.KeyRepo.GetKey(u.ID, keyRef, 2)
	test.RequireErrNotNil(t, err)
	test.RequireContains(t, err.Error(), "no rows")
}

func TestDeleteKey_MissingToken(t *testing.T) {
	u, err := requireClient(appCtx, "keys-delete-missingtoken", "client")
	test.RequireErrNil(t, err)

	keyRef := "db-key"
	key, err := requireKey(appCtx, u.ID, keyRef, 1, keys.StateInUse)
	test.RequireErrNil(t, err)

	resp, err := doRequest("DELETE", "/keys/"+keyRef+"/actions/delete", "")
	requireReqNotFailed(t, err)
	defer resp.Body.Close()

	requireUnauthorized(t, resp)

	// check if key wasn't deleted regardless
	_, err = appCtx.KeyRepo.GetKey(u.ID, key.KeyReference, 1)
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
