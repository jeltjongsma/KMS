package integration

import (
	"fmt"
	"kms/internal/test"
	"strconv"
	"testing"
)

func TestUpdateRole(t *testing.T) {
	admin, err := requireClient(appCtx, "admin", "admin")
	test.RequireErrNil(t, err)

	u, err := requireClient(appCtx, "client", "client")
	test.RequireErrNil(t, err)

	token, err := requireJWT(appCtx, admin)
	test.RequireErrNil(t, err)

	resp, err := doRequest("POST", fmt.Sprintf("/clients/%d/role", u.ID), `{"role":"admin"}`,
		"Authorization", "Bearer "+token)
	requireReqNotFailed(t, err)
	defer resp.Body.Close()

	requireStatusCode(t, resp.StatusCode, 204)

	updatedU, err := appCtx.ClientRepo.FindByHashedClientname(u.HashedClientname)
	test.RequireErrNil(t, err)

	if updatedU.Role != "admin" {
		t.Errorf("expected role: admin, got %s", updatedU.Role)
	}

	if updatedU.ID != u.ID ||
		updatedU.HashedClientname != u.HashedClientname ||
		updatedU.Clientname != u.Clientname ||
		updatedU.Password != u.Password {
		t.Errorf("expected %v, got %v", u, updatedU)
	}
}

func TestUpdateRole_MissingToken(t *testing.T) {
	_, err := requireClient(appCtx, "clients-updaterole-missingtoken-admin", "admin")
	test.RequireErrNil(t, err)

	u, err := requireClient(appCtx, "clients-updaterole-missingtoken-client", "client")
	test.RequireErrNil(t, err)

	resp, err := doRequest("POST", fmt.Sprintf("/clients/%d/role", u.ID), `{"role":"admin"}`)
	requireReqNotFailed(t, err)
	defer resp.Body.Close()

	requireUnauthorized(t, resp)
}

func TestUpdateRole_MissingBody(t *testing.T) {
	admin, err := requireClient(appCtx, "clients-updaterole-missingbody-admin", "admin")
	test.RequireErrNil(t, err)

	u, err := requireClient(appCtx, "clients-updaterole-missingbody-client", "client")
	test.RequireErrNil(t, err)

	token, err := requireJWT(appCtx, admin)
	test.RequireErrNil(t, err)

	resp, err := doRequest("POST", fmt.Sprintf("/clients/%d/role", u.ID), "",
		"Authorization", "Bearer "+token)
	requireReqNotFailed(t, err)
	defer resp.Body.Close()

	requireBadRequest(t, resp)
}

func TestUpdateRole_InvalidRole(t *testing.T) {
	admin, err := requireClient(appCtx, "clients-updaterole-emptyrole-admin", "admin")
	test.RequireErrNil(t, err)

	u, err := requireClient(appCtx, "clients-updaterole-emptyrole-client", "client")
	test.RequireErrNil(t, err)

	token, err := requireJWT(appCtx, admin)
	test.RequireErrNil(t, err)

	resp, err := doRequest("POST", fmt.Sprintf("/clients/%d/role", u.ID), `{"role":""}`,
		"Authorization", "Bearer "+token)
	requireReqNotFailed(t, err)
	defer resp.Body.Close()

	requireBadRequest(t, resp)
}

func TestUpdateRole_NotAdmin(t *testing.T) {
	u, err := requireClient(appCtx, "clients-updaterole-notadmin-client", "client")
	test.RequireErrNil(t, err)

	token, err := requireJWT(appCtx, u)
	test.RequireErrNil(t, err)

	resp, err := doRequest("POST", fmt.Sprintf("/clients/%d/role", u.ID), `{"role":"admin"}`,
		"Authorization", "Bearer "+token)
	requireReqNotFailed(t, err)
	defer resp.Body.Close()

	requireForbidden(t, resp)
}

func TestGetClients(t *testing.T) {
	a, err := requireClient(appCtx, "clients-getclients", "admin")
	test.RequireErrNil(t, err)

	_, err = requireClient(appCtx, "clients-getclients-client", "client")
	test.RequireErrNil(t, err)

	token, err := requireJWT(appCtx, a)
	test.RequireErrNil(t, err)

	resp, err := doRequest("GET", "/clients", "",
		"Authorization", "Bearer "+token)
	requireReqNotFailed(t, err)
	defer resp.Body.Close()

	body := GetBody(resp)
	test.RequireContains(t, body, `"clientname":"clients-getclients-client"`)
	test.RequireContains(t, body, `"clientname":"clients-getclients"`)
}

func TestGetClients_NotAdmin(t *testing.T) {
	u, err := requireClient(appCtx, "clients-getclients-notadmin", "client")
	test.RequireErrNil(t, err)

	token, err := requireJWT(appCtx, u)
	test.RequireErrNil(t, err)

	resp, err := doRequest("GET", "/clients", "",
		"Authorization", "Bearer "+token)
	requireReqNotFailed(t, err)
	defer resp.Body.Close()

	requireForbidden(t, resp)
}

func TestGetClients_MissingToken(t *testing.T) {
	resp, err := doRequest("GET", "/clients", "")
	requireReqNotFailed(t, err)
	defer resp.Body.Close()

	requireUnauthorized(t, resp)
}

func TestDeleteClient(t *testing.T) {
	a, err := requireClient(appCtx, "clients-deleteclient", "admin")
	test.RequireErrNil(t, err)

	u, err := requireClient(appCtx, "clients-deleteclient-client", "client")
	test.RequireErrNil(t, err)

	token, err := requireJWT(appCtx, a)
	test.RequireErrNil(t, err)

	resp, err := doRequest("DELETE", "/clients/"+strconv.Itoa(u.ID), "",
		"Authorization", "Bearer "+token)
	requireReqNotFailed(t, err)
	defer resp.Body.Close()

	_, err = appCtx.ClientRepo.FindByHashedClientname(u.HashedClientname)
	test.RequireErrNotNil(t, err)
	test.RequireContains(t, err.Error(), "no rows")
}

func TestDeleteClient_NotAdmin(t *testing.T) {
	u, err := requireClient(appCtx, "clients-deleteclient-client", "client")
	test.RequireErrNil(t, err)

	token, err := requireJWT(appCtx, u)
	test.RequireErrNil(t, err)

	resp, err := doRequest("DELETE", "/clients/"+strconv.Itoa(u.ID), "",
		"Authorization", "Bearer "+token)
	requireReqNotFailed(t, err)
	defer resp.Body.Close()

	requireForbidden(t, resp)
}

func TestDeleteClient_MissingToken(t *testing.T) {
	u, err := requireClient(appCtx, "clients-deleteclient-client-missingtoken", "client")
	test.RequireErrNil(t, err)

	resp, err := doRequest("DELETE", "/clients/12", "")
	requireReqNotFailed(t, err)
	defer resp.Body.Close()

	requireUnauthorized(t, resp)

	_, err = appCtx.ClientRepo.FindByHashedClientname(u.HashedClientname)
	test.RequireErrNil(t, err)
}
