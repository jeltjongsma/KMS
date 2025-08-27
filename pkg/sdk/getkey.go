package sdk

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"time"
)

type KeyBundle struct {
	DecryptWith *Key `json:"decryptWith"`
	EncryptWith *Key `json:"encryptWith"`
}

type Key struct {
	DEK       string    `json:"dek"`
	Version   int       `json:"version"`
	Encoding  string    `json:"encoding"`
	ExpiresAt time.Time `json:"expiresAt"`
}

func (c *Client) GetKey(keyReference string, version int) (*KeyBundle, error) {
	if err := c.tokenOrLogin(); err != nil {
		return nil, err
	}

	url := c.base + fmt.Sprintf("/keys/%s/%d", keyReference, version)
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+c.token)

	resp, err := c.http.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusUnauthorized {
		// Token might be expired, refresh and retry once
		if err := c.forceRefresh(); err != nil {
			return nil, err
		}
		req.Header.Set("Authorization", "Bearer "+c.token)
		resp, err = c.http.Do(req)
		if err != nil {
			return nil, err
		}
	}

	if resp.StatusCode != http.StatusOK {
		return nil, errors.New("failed to get key: " + resp.Status)
	}

	var bundle KeyBundle
	if err := json.NewDecoder(resp.Body).Decode(&bundle); err != nil {
		return nil, err
	}

	return &bundle, nil
}
