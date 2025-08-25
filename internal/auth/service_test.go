package auth

import (
	"database/sql"
	"errors"
	c "kms/internal/bootstrap/context"
	"kms/internal/clients"
	"kms/internal/test/mocks"
	"kms/pkg/hashing"
	"strings"
	"testing"
)

func TestService_Signup_Success(t *testing.T) {
	mockRepo := clients.NewClientRepositoryMock()
	mockRepo.CreateClientFunc = func(client *clients.Client) (int, error) {
		return 1, nil
	}
	mockLogger := mocks.NewLoggerMock()
	mockKeyManager := mocks.NewKeyManagerMock()
	signupSecret := []byte("signupsecret")
	mockKeyManager.SignupKeyFunc = func() []byte {
		return signupSecret
	}
	mockKeyManager.HashKeyFunc = func(key string) ([]byte, error) {
		return []byte("clientnamesecret"), nil
	}

	cfg := c.KmsConfig{
		"DEFAULT_ROLE": "client",
	}

	tokenGenInfo := &TokenGenInfo{
		Ttl:    3600,
		Secret: signupSecret,
		Typ:    "signup",
	}

	service := NewService(cfg, mockRepo, tokenGenInfo, mockKeyManager, mockLogger)

	token, err := GenerateSignupToken(tokenGenInfo, "testclient")
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	cred := &SignupCredentials{
		Token:    token,
		Password: "Valid123!1234",
	}

	jwt, appErr := service.Signup(cred)
	if appErr != nil {
		t.Fatalf("expected no error, got %v", appErr)
	}

	if jwt == "" {
		t.Error("expected non-empty JWT, got empty string")
	}
}

func TestService_Signup_InvalidTokenError(t *testing.T) {
	mockRepo := clients.NewClientRepositoryMock()
	mockLogger := mocks.NewLoggerMock()
	mockKeyManager := mocks.NewKeyManagerMock()
	signupSecret := []byte("signupsecret")
	mockKeyManager.SignupKeyFunc = func() []byte {
		return signupSecret
	}
	mockKeyManager.HashKeyFunc = func(key string) ([]byte, error) {
		return []byte("clientnamesecret"), nil
	}
	cfg := c.KmsConfig{
		"DEFAULT_ROLE": "client",
	}
	tokenGenInfo := &TokenGenInfo{
		Ttl:    3600,
		Secret: signupSecret,
		Typ:    "signup",
	}

	service := NewService(cfg, mockRepo, tokenGenInfo, mockKeyManager, mockLogger)

	cred := &SignupCredentials{
		Token:    "invalidtoken",
		Password: "Valid123!1234",
	}

	_, appErr := service.Signup(cred)
	if appErr == nil {
		t.Fatal("expected error for invalid token, got nil")
	}
	if appErr.Code != 401 {
		t.Errorf("expected error code 401, got %d", appErr.Code)
	}
}

func TestService_Signup_WrongTokenTyp(t *testing.T) {
	mockRepo := clients.NewClientRepositoryMock()
	mockLogger := mocks.NewLoggerMock()
	mockKeyManager := mocks.NewKeyManagerMock()
	signupSecret := []byte("signupsecret")
	mockKeyManager.SignupKeyFunc = func() []byte {
		return signupSecret
	}
	cfg := c.KmsConfig{
		"DEFAULT_ROLE": "client",
	}

	tokenGenInfo := &TokenGenInfo{
		Ttl:    3600,
		Secret: signupSecret,
		Typ:    "jwt",
	}

	service := NewService(cfg, mockRepo, tokenGenInfo, mockKeyManager, mockLogger)

	token, err := GenerateSignupToken(tokenGenInfo, "testclient")
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	cred := &SignupCredentials{
		Token:    token,
		Password: "Valid123!1234",
	}

	_, appErr := service.Signup(cred)
	if appErr == nil {
		t.Fatal("expected error for invalid token type, got nil")
	}
	if appErr.Code != 400 {
		t.Errorf("expected statuscode 400, got %d", appErr.Code)
	}
}

func TestService_Signup_InvalidPasswordError(t *testing.T) {
	mockRepo := clients.NewClientRepositoryMock()
	mockLogger := mocks.NewLoggerMock()
	mockKeyManager := mocks.NewKeyManagerMock()
	signupSecret := []byte("signupsecret")
	mockKeyManager.SignupKeyFunc = func() []byte {
		return signupSecret
	}
	mockKeyManager.HashKeyFunc = func(key string) ([]byte, error) {
		return []byte("clientnamesecret"), nil
	}
	cfg := c.KmsConfig{
		"DEFAULT_ROLE": "client",
	}
	tokenGenInfo := &TokenGenInfo{
		Ttl:    3600,
		Secret: signupSecret,
		Typ:    "signup",
	}
	service := NewService(cfg, mockRepo, tokenGenInfo, mockKeyManager, mockLogger)
	token, err := GenerateSignupToken(tokenGenInfo, "testclient")
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	cred := &SignupCredentials{
		Token:    token,
		Password: "short",
	}
	_, appErr := service.Signup(cred)
	if appErr == nil {
		t.Fatal("expected error for invalid password, got nil")
	}
	if appErr.Code != 400 {
		t.Errorf("expected error code 400, got %d", appErr.Code)
	}
}

func TestService_Signup_RepoError(t *testing.T) {
	mockRepo := clients.NewClientRepositoryMock()
	mockRepo.CreateClientFunc = func(client *clients.Client) (int, error) {
		return 0, errors.New("repo error")
	}
	mockLogger := mocks.NewLoggerMock()
	mockKeyManager := mocks.NewKeyManagerMock()
	signupSecret := []byte("signupsecret")
	mockKeyManager.SignupKeyFunc = func() []byte {
		return signupSecret
	}
	mockKeyManager.HashKeyFunc = func(key string) ([]byte, error) {
		return []byte("clientnamesecret"), nil
	}
	cfg := c.KmsConfig{
		"DEFAULT_ROLE": "client",
	}
	tokenGenInfo := &TokenGenInfo{
		Ttl:    3600,
		Secret: signupSecret,
		Typ:    "signup",
	}
	service := NewService(cfg, mockRepo, tokenGenInfo, mockKeyManager, mockLogger)
	token, err := GenerateSignupToken(tokenGenInfo, "testclient")
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	cred := &SignupCredentials{
		Token:    token,
		Password: "Valid123!1234",
	}

	_, appErr := service.Signup(cred)
	if appErr == nil {
		t.Fatal("expected error for repository failure, got nil")
	}
	if appErr.Code != 500 {
		t.Errorf("expected error code 500, got %d", appErr.Code)
	}
}

func TestService_Login_Success(t *testing.T) {
	mockRepo := clients.NewClientRepositoryMock()
	hashedPassword, _ := hashing.HashPassword("Valid123!1234")
	mockRepo.FindByHashedClientnameFunc = func(clientname string) (*clients.Client, error) {
		return &clients.Client{
			ID:               1,
			Clientname:       "testclient",
			HashedClientname: "hashedclientname",
			Password:         hashedPassword,
			Role:             "client",
		}, nil
	}
	mockLogger := mocks.NewLoggerMock()
	mockKeyManager := mocks.NewKeyManagerMock()
	clientnameSecret := []byte("clientnamesecret")
	mockKeyManager.HashKeyFunc = func(key string) ([]byte, error) {
		return clientnameSecret, nil
	}

	cfg := c.KmsConfig{
		"DEFAULT_ROLE": "client",
	}

	tokenGenInfo := &TokenGenInfo{
		Ttl:    3600,
		Secret: clientnameSecret,
		Typ:    "jwt",
	}

	service := NewService(cfg, mockRepo, tokenGenInfo, mockKeyManager, mockLogger)

	loginCreds := &Credentials{
		Clientname: "testclient",
		Password:   "Valid123!1234",
	}

	jwt, appErr := service.Login(loginCreds)
	if appErr != nil {
		t.Fatalf("expected no error, got %v", appErr)
	}

	if jwt == "" {
		t.Error("expected non-empty JWT, got empty string")
	}
}

func TestService_Login_KeyManagerError(t *testing.T) {
	mockRepo := clients.NewClientRepositoryMock()
	mockLogger := mocks.NewLoggerMock()
	mockKeyManager := mocks.NewKeyManagerMock()
	mockKeyManager.HashKeyFunc = func(key string) ([]byte, error) {
		return nil, errors.New("key manager error")
	}
	cfg := c.KmsConfig{
		"DEFAULT_ROLE": "client",
	}
	tokenGenInfo := &TokenGenInfo{
		Ttl:    3600,
		Secret: []byte("secret"),
		Typ:    "jwt",
	}
	service := NewService(cfg, mockRepo, tokenGenInfo, mockKeyManager, mockLogger)

	loginCreds := &Credentials{
		Clientname: "testclient",
		Password:   "Valid123!1234",
	}

	_, appErr := service.Login(loginCreds)
	if appErr == nil {
		t.Fatal("expected error for key manager failure, got nil")
	}
	if appErr.Code != 500 {
		t.Errorf("expected error code 500, got %d", appErr.Code)
	}
}

func TestService_Login_ClientNotFound(t *testing.T) {
	mockRepo := clients.NewClientRepositoryMock()
	mockRepo.FindByHashedClientnameFunc = func(clientname string) (*clients.Client, error) {
		return nil, sql.ErrNoRows
	}
	mockLogger := mocks.NewLoggerMock()
	mockKeyManager := mocks.NewKeyManagerMock()
	mockKeyManager.HashKeyFunc = func(key string) ([]byte, error) {
		return []byte("clientnamesecret"), nil
	}
	cfg := c.KmsConfig{
		"DEFAULT_ROLE": "client",
	}
	tokenGenInfo := &TokenGenInfo{
		Ttl:    3600,
		Secret: []byte("secret"),
		Typ:    "jwt",
	}
	service := NewService(cfg, mockRepo, tokenGenInfo, mockKeyManager, mockLogger)

	loginCreds := &Credentials{
		Clientname: "testclient",
		Password:   "Valid123!1234",
	}

	_, appErr := service.Login(loginCreds)
	if appErr == nil {
		t.Fatal("expected error for client not found, got nil")
	}
	if appErr.Code != 401 {
		t.Errorf("expected error code 401, got %d", appErr.Code)
	}
	if appErr.Message != "Incorrect clientname or password" {
		t.Errorf("expected error message 'Incorrect clientname or password', got '%s'", appErr.Message)
	}
}

func TestService_Login_InvalidPassword(t *testing.T) {
	mockRepo := clients.NewClientRepositoryMock()
	hashedPassword, _ := hashing.HashPassword("Valid123!1234")
	mockRepo.FindByHashedClientnameFunc = func(clientname string) (*clients.Client, error) {
		return &clients.Client{
			ID:               1,
			Clientname:       "testclient",
			HashedClientname: "hashedclientname",
			Password:         hashedPassword,
			Role:             "client",
		}, nil
	}
	mockLogger := mocks.NewLoggerMock()
	mockKeyManager := mocks.NewKeyManagerMock()
	mockKeyManager.HashKeyFunc = func(key string) ([]byte, error) {
		return []byte("clientnamesecret"), nil
	}
	cfg := c.KmsConfig{
		"DEFAULT_ROLE": "client",
	}
	tokenGenInfo := &TokenGenInfo{
		Ttl:    3600,
		Secret: []byte("secret"),
		Typ:    "jwt",
	}
	service := NewService(cfg, mockRepo, tokenGenInfo, mockKeyManager, mockLogger)

	loginCreds := &Credentials{
		Clientname: "testclient",
		Password:   "WrongPassword123!",
	}

	_, appErr := service.Login(loginCreds)
	if appErr == nil {
		t.Fatal("expected error for invalid password, got nil")
	}
	if appErr.Code != 401 {
		t.Errorf("expected error code 401, got %d", appErr.Code)
	}
	if appErr.Message != "Incorrect clientname or password" {
		t.Errorf("expected error message 'Incorrect clientname or password', got '%s'", appErr.Message)
	}
}

func TestValidatePassword(t *testing.T) {
	cases := []struct {
		password string
		wantErr  bool
		desc     string
	}{
		{"short1A!", true, "too short"},
		{strings.Repeat("a", 129), true, "too long"},
		{"alllowercasepassword", true, "no upper, digit, sym"},
		{"ALLUPPERCASEPASSWORD", true, "no lower, digit, sym"},
		{"123456789012", true, "only digits"},
		{"!!!!!!!!!!!!", true, "only symbols"},
		{"PasswordNoSym1", false, "upper, lower, digit"},
		{"Password!NoDigit", false, "upper, lower, sym"},
		{"password!1", true, "too short, but has lower, sym, digit"},
		{"Password!1", true, "upper, lower, sym, digit, invalid length"},
		{"Pass!word123", false, "upper, lower, sym, digit, valid"},
		{"Pass!wordabc", false, "upper, lower, sym, valid, but only 3 types"},
		{"Pass1wordabc", false, "upper, lower, digit, valid, only 3 types"},
		{"PASSWORD!123", false, "upper, sym, digit, valid, only 3 types"},
		{"password!1AB", false, "lower, sym, digit, upper, valid"},
	}
	for _, tc := range cases {
		err := validatePassword(tc.password)
		if (err != nil) != tc.wantErr {
			t.Errorf("%s: validatePassword(%q) error = %v, wantErr %v", tc.desc, tc.password, err, tc.wantErr)
		}
	}
}
