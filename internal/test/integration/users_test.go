package integration

import (
	"fmt"
	"kms/internal/test"
	"strconv"
	"testing"
)

func TestUpdateRole(t *testing.T) {
	admin, err := requireUser(appCtx, "admin", "admin")
	test.RequireErrNil(t, err)

	u, err := requireUser(appCtx, "user", "user")
	test.RequireErrNil(t, err)

	token, err := requireJWT(appCtx, admin)
	test.RequireErrNil(t, err)

	resp, err := doRequest("POST", fmt.Sprintf("/users/%d/role", u.ID), `{"role":"admin"}`,
		"Authorization", "Bearer "+token)
	requireReqNotFailed(t, err)
	defer resp.Body.Close()

	requireStatusCode(t, resp.StatusCode, 204)

	updatedU, err := appCtx.UserRepo.FindByHashedUsername(u.HashedUsername)
	test.RequireErrNil(t, err)

	if updatedU.Role != "admin" {
		t.Errorf("expected role: admin, got %s", updatedU.Role)
	}

	if updatedU.ID != u.ID ||
		updatedU.HashedUsername != u.HashedUsername ||
		updatedU.Username != u.Username ||
		updatedU.Password != u.Password {
		t.Errorf("expected %v, got %v", u, updatedU)
	}
}

func TestUpdateRole_MissingToken(t *testing.T) {
	_, err := requireUser(appCtx, "users-updaterole-missingtoken-admin", "admin")
	test.RequireErrNil(t, err)

	u, err := requireUser(appCtx, "users-updaterole-missingtoken-user", "user")
	test.RequireErrNil(t, err)

	resp, err := doRequest("POST", fmt.Sprintf("/users/%d/role", u.ID), `{"role":"admin"}`)
	requireReqNotFailed(t, err)
	defer resp.Body.Close()

	requireUnauthorized(t, resp)
}

func TestUpdateRole_MissingBody(t *testing.T) {
	admin, err := requireUser(appCtx, "users-updaterole-missingbody-admin", "admin")
	test.RequireErrNil(t, err)

	u, err := requireUser(appCtx, "users-updaterole-missingbody-user", "user")
	test.RequireErrNil(t, err)

	token, err := requireJWT(appCtx, admin)
	test.RequireErrNil(t, err)

	resp, err := doRequest("POST", fmt.Sprintf("/users/%d/role", u.ID), "",
		"Authorization", "Bearer "+token)
	requireReqNotFailed(t, err)
	defer resp.Body.Close()

	requireBadRequest(t, resp)
}

func TestUpdateRole_InvalidRole(t *testing.T) {
	admin, err := requireUser(appCtx, "users-updaterole-emptyrole-admin", "admin")
	test.RequireErrNil(t, err)

	u, err := requireUser(appCtx, "users-updaterole-emptyrole-user", "user")
	test.RequireErrNil(t, err)

	token, err := requireJWT(appCtx, admin)
	test.RequireErrNil(t, err)

	resp, err := doRequest("POST", fmt.Sprintf("/users/%d/role", u.ID), `{"role":""}`,
		"Authorization", "Bearer "+token)
	requireReqNotFailed(t, err)
	defer resp.Body.Close()

	requireBadRequest(t, resp)
}

func TestGenerateSignupToken(t *testing.T) {
	u, err := requireUser(appCtx, "users-gensignup", "admin")
	test.RequireErrNil(t, err)

	token, err := requireJWT(appCtx, u)
	test.RequireErrNil(t, err)

	resp, err := doRequest("POST", "/users/tokens/generate", `{"ttl":3600,"username":"iot-device"}`,
		"Authorization", "Bearer "+token)
	requireReqNotFailed(t, err)
	defer resp.Body.Close()

	requireStatusCode(t, resp.StatusCode, 200)
	test.RequireContains(t, GetBody(resp), `"token":`)
}

func TestGenerateSignupToken_MissingToken(t *testing.T) {
	_, err := requireUser(appCtx, "users-gensignup-missingtoken", "admin")
	test.RequireErrNil(t, err)

	resp, err := doRequest("POST", "/users/tokens/generate", `{"ttl":3600,"username":"iot-device"}`)
	requireReqNotFailed(t, err)
	defer resp.Body.Close()

	requireUnauthorized(t, resp)
}

func TestGenerateSignupToken_MissingBody(t *testing.T) {
	u, err := requireUser(appCtx, "users-gensignup-missingbody", "admin")
	test.RequireErrNil(t, err)

	token, err := requireJWT(appCtx, u)
	test.RequireErrNil(t, err)

	resp, err := doRequest("POST", "/users/tokens/generate", "",
		"Authorization", "Bearer "+token)
	requireReqNotFailed(t, err)
	defer resp.Body.Close()

	requireBadRequest(t, resp)
}

func TestGetUsers(t *testing.T) {
	a, err := requireUser(appCtx, "users-getusers", "admin")
	test.RequireErrNil(t, err)

	_, err = requireUser(appCtx, "users-getusers-user", "user")
	test.RequireErrNil(t, err)

	token, err := requireJWT(appCtx, a)
	test.RequireErrNil(t, err)

	resp, err := doRequest("GET", "/users", "",
		"Authorization", "Bearer "+token)
	requireReqNotFailed(t, err)
	defer resp.Body.Close()

	body := GetBody(resp)
	test.RequireContains(t, body, `"username":"users-getusers-user"`)
	test.RequireContains(t, body, `"username":"users-getusers"`)
}

func TestGetUsers_NotAdmin(t *testing.T) {
	u, err := requireUser(appCtx, "users-getusers-notadmin", "user")
	test.RequireErrNil(t, err)

	token, err := requireJWT(appCtx, u)
	test.RequireErrNil(t, err)

	resp, err := doRequest("GET", "/users", "",
		"Authorization", "Bearer "+token)
	requireReqNotFailed(t, err)
	defer resp.Body.Close()

	requireForbidden(t, resp)
}

func TestGetUsers_MissingToken(t *testing.T) {
	resp, err := doRequest("GET", "/users", "")
	requireReqNotFailed(t, err)
	defer resp.Body.Close()

	requireUnauthorized(t, resp)
}

func TestDeleteUser(t *testing.T) {
	a, err := requireUser(appCtx, "users-deleteuser", "admin")
	test.RequireErrNil(t, err)

	u, err := requireUser(appCtx, "users-deleteuser-user", "user")
	test.RequireErrNil(t, err)

	token, err := requireJWT(appCtx, a)
	test.RequireErrNil(t, err)

	resp, err := doRequest("DELETE", "/users/"+strconv.Itoa(u.ID), "",
		"Authorization", "Bearer "+token)
	requireReqNotFailed(t, err)
	defer resp.Body.Close()

	_, err = appCtx.UserRepo.FindByHashedUsername(u.HashedUsername)
	test.RequireErrNotNil(t, err)
	test.RequireContains(t, err.Error(), "no rows")
}

func TestDeleteUser_NotAdmin(t *testing.T) {
	u, err := requireUser(appCtx, "users-deleteuser-user", "user")
	test.RequireErrNil(t, err)

	token, err := requireJWT(appCtx, u)
	test.RequireErrNil(t, err)

	resp, err := doRequest("DELETE", "/users/"+strconv.Itoa(u.ID), "",
		"Authorization", "Bearer "+token)
	requireReqNotFailed(t, err)
	defer resp.Body.Close()

	requireForbidden(t, resp)
}

func TestDeleteUser_MissingToken(t *testing.T) {
	u, err := requireUser(appCtx, "users-deleteuser-user-missingtoken", "user")
	test.RequireErrNil(t, err)

	resp, err := doRequest("DELETE", "/users/12", "")
	requireReqNotFailed(t, err)
	defer resp.Body.Close()

	requireUnauthorized(t, resp)

	_, err = appCtx.UserRepo.FindByHashedUsername(u.HashedUsername)
	test.RequireErrNil(t, err)
}
