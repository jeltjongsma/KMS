package integration

import (
	"fmt"
	"kms/internal/test"
	"kms/pkg/hashing"
	"testing"
)

func TestAdminLogin(t *testing.T) {
	resp, err := doRequest("POST", "/auth/login", `{"clientname":"admin@kms.local","password":"securePassword"}`,
		"Content-Type", "application/json")
	requireReqNotFailed(t, err)
	defer resp.Body.Close()

	requireStatusCode(t, resp.StatusCode, 200)
	test.RequireContains(t, GetBody(resp), `"token":`)
}

func TestLogin_IncorrectCredentials(t *testing.T) {
	tests := []struct {
		name       string
		clientname string
		password   string
	}{
		{"wrong clientname", "abcdef", "securePassword"},
		{"wrong password", "admin@kms.local", "wrongPassword"},
		{"both wrong", "abcdef", "wrongPassword"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resp, err := doRequest("POST", "/auth/login", fmt.Sprintf(`{"clientname": "%s","password":"%s"}`, tt.clientname, tt.password),
				"Content-Type", "application/json")
			requireReqNotFailed(t, err)
			defer resp.Body.Close()

			requireStatusCode(t, resp.StatusCode, 401)
			test.RequireContains(t, GetBody(resp), "Incorrect clientname or password")
		})
	}
}

func TestSignup(t *testing.T) {
	clientname := "auth-signup"
	token, err := requireSignupToken(appCtx, clientname)
	test.RequireErrNil(t, err)

	resp, err := doRequest("POST", "/auth/signup", fmt.Sprintf(`{"token":"%s", "password":"SecurePassword01"}`, token))
	requireReqNotFailed(t, err)
	defer resp.Body.Close()

	requireStatusCode(t, resp.StatusCode, 200)
	test.RequireContains(t, GetBody(resp), `"token":`)

	clientHashKey, err := appCtx.KeyManager.HashKey("clientname")
	test.RequireErrNil(t, err)

	// check if client was added to db
	client, err := appCtx.ClientRepo.FindByHashedClientname(hashing.HashHS256ToB64([]byte(clientname), clientHashKey))
	test.RequireErrNil(t, err)

	// check if clientname copied correctly
	if client.Clientname != clientname {
		t.Errorf("expected clientname: %s, got %s", clientname, client.Clientname)
	}
	// check if role was properly set
	if client.Role != appCtx.Cfg["DEFAULT_ROLE"] {
		t.Errorf("expected role: %s, got %s", appCtx.Cfg["DEFAULT_ROLE"], client.Role)
	}
}

func TestSignup_InvalidToken(t *testing.T) {
	resp, err := doRequest("POST", "/auth/signup", `{"token":"invalid.token", "password":"SecurePassword01"}`)
	requireReqNotFailed(t, err)
	defer resp.Body.Close()

	requireUnauthorized(t, resp)
}

func TestSignup_InvalidPassword(t *testing.T) {
	clientname := "auth-signup-invalidpassword"
	token, err := requireSignupToken(appCtx, clientname)
	test.RequireErrNil(t, err)

	resp, err := doRequest("POST", "/auth/signup", fmt.Sprintf(`{"token":"%s", "password":"invalidpassword"}`, token))
	requireReqNotFailed(t, err)
	defer resp.Body.Close()

	requireStatusCode(t, resp.StatusCode, 400)
	test.RequireContains(t, GetBody(resp), "Password does not meet minimum requirements")
}

func TestGenerateSignupToken(t *testing.T) {
	u, err := requireClient(appCtx, "auth-gensignup", "admin")
	test.RequireErrNil(t, err)

	token, err := requireJWT(appCtx, u)
	test.RequireErrNil(t, err)

	resp, err := doRequest("POST", "/auth/signup/generate", `{"ttl":3600,"clientname":"iot-device"}`,
		"Authorization", "Bearer "+token)
	requireReqNotFailed(t, err)
	defer resp.Body.Close()

	requireStatusCode(t, resp.StatusCode, 200)
	test.RequireContains(t, GetBody(resp), `"token":`)
}

func TestGenerateSignupToken_MissingToken(t *testing.T) {
	_, err := requireClient(appCtx, "auth-gensignup-missingtoken", "admin")
	test.RequireErrNil(t, err)

	resp, err := doRequest("POST", "/auth/signup/generate", `{"ttl":3600,"clientname":"iot-device"}`)
	requireReqNotFailed(t, err)
	defer resp.Body.Close()

	requireUnauthorized(t, resp)
}

func TestGenerateSignupToken_MissingBody(t *testing.T) {
	u, err := requireClient(appCtx, "auth-gensignup-missingbody", "admin")
	test.RequireErrNil(t, err)

	token, err := requireJWT(appCtx, u)
	test.RequireErrNil(t, err)

	resp, err := doRequest("POST", "/auth/signup/generate", "",
		"Authorization", "Bearer "+token)
	requireReqNotFailed(t, err)
	defer resp.Body.Close()

	requireBadRequest(t, resp)
}

func TestGenerateSignupToken_NotAdmin(t *testing.T) {
	u, err := requireClient(appCtx, "auth-gensignup-notadmin", "client")
	test.RequireErrNil(t, err)

	token, err := requireJWT(appCtx, u)
	test.RequireErrNil(t, err)

	resp, err := doRequest("POST", "/auth/signup/generate", `{"ttl":3600,"clientname":"iot-device"}`,
		"Authorization", "Bearer "+token)
	requireReqNotFailed(t, err)
	defer resp.Body.Close()

	requireForbidden(t, resp)
}
