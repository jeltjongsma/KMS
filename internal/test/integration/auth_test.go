package integration

import (
	"fmt"
	"kms/internal/test"
	"kms/pkg/hashing"
	"testing"
)

func TestAdminLogin(t *testing.T) {
	resp, err := doRequest("POST", "/auth/login", `{"username":"admin@kms.local","password":"securePassword"}`,
		"Content-Type", "application/json")
	requireReqNotFailed(t, err)
	defer resp.Body.Close()

	requireStatusCode(t, resp.StatusCode, 200)
	test.RequireContains(t, GetBody(resp), `"token":`)
}

func TestLogin_IncorrectCredentials(t *testing.T) {
	tests := []struct {
		name     string
		username string
		password string
	}{
		{"wrong username", "abcdef", "securePassword"},
		{"wrong password", "admin@kms.local", "wrongPassword"},
		{"both wrong", "abcdef", "wrongPassword"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resp, err := doRequest("POST", "/auth/login", fmt.Sprintf(`{"username": "%s","password":"%s"}`, tt.username, tt.password),
				"Content-Type", "application/json")
			requireReqNotFailed(t, err)
			defer resp.Body.Close()

			requireStatusCode(t, resp.StatusCode, 401)
			test.RequireContains(t, GetBody(resp), "Incorrect username or password")
		})
	}
}

func TestSignup(t *testing.T) {
	username := "auth-signup"
	token, err := requireSignupToken(appCtx, username)
	test.RequireErrNil(t, err)

	resp, err := doRequest("POST", "/auth/signup", fmt.Sprintf(`{"token":"%s", "password":"SecurePassword01"}`, token))
	requireReqNotFailed(t, err)
	defer resp.Body.Close()

	requireStatusCode(t, resp.StatusCode, 200)
	test.RequireContains(t, GetBody(resp), `"token":`)

	userHashKey, err := appCtx.KeyManager.HashKey("username")
	test.RequireErrNil(t, err)

	// check if user was added to db
	user, err := appCtx.UserRepo.FindByHashedUsername(hashing.HashHS256ToB64([]byte(username), userHashKey))
	test.RequireErrNil(t, err)

	// check if username copied correctly
	if user.Username != username {
		t.Errorf("expected username: %s, got %s", username, user.Username)
	}
	// check if role was properly set
	if user.Role != appCtx.Cfg["DEFAULT_ROLE"] {
		t.Errorf("expected role: %s, got %s", appCtx.Cfg["DEFAULT_ROLE"], user.Role)
	}
}

func TestSignup_InvalidToken(t *testing.T) {
	resp, err := doRequest("POST", "/auth/signup", `{"token":"invalid.token", "password":"SecurePassword01"}`)
	requireReqNotFailed(t, err)
	defer resp.Body.Close()

	requireUnauthorized(t, resp)
}

func TestSignup_InvalidPassword(t *testing.T) {
	username := "auth-signup-invalidpassword"
	token, err := requireSignupToken(appCtx, username)
	test.RequireErrNil(t, err)

	resp, err := doRequest("POST", "/auth/signup", fmt.Sprintf(`{"token":"%s", "password":"invalidpassword"}`, token))
	requireReqNotFailed(t, err)
	defer resp.Body.Close()

	requireStatusCode(t, resp.StatusCode, 400)
	test.RequireContains(t, GetBody(resp), "Password does not meet minimum requirements")
}
