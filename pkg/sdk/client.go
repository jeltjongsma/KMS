package sdk

import (
	"crypto/tls"
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"
)

type Client struct {
	base string
	user string
	pass string
	http *http.Client

	mu        sync.RWMutex
	token     string
	expiresAt time.Time
}

var ErrMissingConfig = errors.New("missing configuration: KMS_BASE_URL, KMS_USER, KMS_PASS must be set")

func NewClient() (*Client, error) {
	base := os.Getenv("KMS_BASE_URL")
	user := os.Getenv("KMS_USER")
	pass := os.Getenv("KMS_PASS")
	if base == "" || user == "" || pass == "" {
		return nil, ErrMissingConfig
	}

	// Allow skipping TLS verification for local testing
	// (not recommended for production use)
	var tr *http.Transport
	skipVerify := os.Getenv("KMS_INSECURE_SKIP_VERIFY") == "true"
	if skipVerify {
		tr = &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		}
	}

	return &Client{
		base: strings.TrimRight(base, "/"),
		user: user,
		pass: pass,
		http: &http.Client{
			Timeout:   10 * time.Second,
			Transport: tr,
		},
	}, nil
}

func (c *Client) tokenOrLogin() error {
	c.mu.RLock()
	if c.token != "" && time.Now().Before(c.expiresAt) {
		return nil
	}
	c.mu.RUnlock()

	loginBody := map[string]string{
		"clientname": c.user,
		"password":   c.pass,
	}
	bodyBytes, err := json.Marshal(loginBody)
	if err != nil {
		return err
	}

	req, err := http.NewRequest("POST", c.base+"/auth/login", strings.NewReader(string(bodyBytes)))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.http.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return errors.New("login failed: " + resp.Status)
	}

	var respBody struct {
		Token string `json:"token"`
		Ttl   int    `json:"ttl"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&respBody); err != nil {
		return err
	}

	c.mu.Lock()
	c.token = respBody.Token
	c.expiresAt = time.Now().Add(time.Duration(respBody.Ttl))
	c.mu.Unlock()

	return nil
}

func (c *Client) forceRefresh() error {
	c.mu.Lock()
	c.token = ""
	c.expiresAt = time.Time{}
	c.mu.Unlock()

	return c.tokenOrLogin()
}
