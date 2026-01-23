package registry

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
)

// TestTokenTransport_Auth_Success_DockerToken tests successful authentication with Docker token format
func TestTokenTransport_Auth_Success_DockerToken(t *testing.T) {
	authServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"token": "valid-token-123"}`))
	}))
	t.Cleanup(authServer.Close)

	transport := &TokenTransport{
		Transport: http.DefaultTransport,
		Username:  "testuser",
		Password:  "testpass",
	}

	authService := &authService{
		Realm:   authServer.URL,
		Service: "test-service",
		Scope:   "repository:test/repo:pull",
	}

	token, resp, err := transport.auth(authService)
	if err != nil {
		t.Fatalf("Expected no error, got: %v", err)
	}
	if resp != nil {
		t.Errorf("Expected nil response, got: %v", resp)
	}
	if token != "valid-token-123" {
		t.Errorf("Expected token 'valid-token-123', got: %q", token)
	}
}

// TestTokenTransport_Auth_Success_OAuth2AccessToken tests successful authentication with OAuth2 access_token format
func TestTokenTransport_Auth_Success_OAuth2AccessToken(t *testing.T) {
	authServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"access_token": "valid-access-token-456"}`))
	}))
	t.Cleanup(authServer.Close)

	transport := &TokenTransport{
		Transport: http.DefaultTransport,
		Username:  "testuser",
		Password:  "testpass",
	}

	authService := &authService{
		Realm:   authServer.URL,
		Service: "test-service",
		Scope:   "repository:test/repo:pull",
	}

	token, resp, err := transport.auth(authService)
	if err != nil {
		t.Fatalf("Expected no error, got: %v", err)
	}
	if resp != nil {
		t.Errorf("Expected nil response, got: %v", resp)
	}
	if token != "valid-access-token-456" {
		t.Errorf("Expected token 'valid-access-token-456', got: %q", token)
	}
}

// TestTokenTransport_Auth_Failure_401Unauthorized tests that auth() returns error on 401 (CRITICAL BUG FIX TEST)
func TestTokenTransport_Auth_Failure_401Unauthorized(t *testing.T) {
	authServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		w.Write([]byte(`{"errors":[{"code":"UNAUTHORIZED","message":"authentication failed"}]}`))
	}))
	t.Cleanup(authServer.Close)

	transport := &TokenTransport{
		Transport: http.DefaultTransport,
		Username:  "baduser",
		Password:  "badpass",
	}

	authService := &authService{
		Realm:   authServer.URL,
		Service: "test-service",
		Scope:   "repository:test/repo:pull",
	}

	token, resp, err := transport.auth(authService)

	// CRITICAL: Error must NOT be nil (this is the bug we're fixing)
	if err == nil {
		t.Fatal("Expected error for 401 status, got nil")
	}

	// Verify error is HttpStatusError
	httpErr, ok := err.(*HttpStatusError)
	if !ok {
		t.Fatalf("Expected *HttpStatusError, got: %T", err)
	}

	// Verify status code in error
	if httpErr.Response.StatusCode != http.StatusUnauthorized {
		t.Errorf("Expected status 401, got: %d", httpErr.Response.StatusCode)
	}

	// Verify token is empty
	if token != "" {
		t.Errorf("Expected empty token, got: %q", token)
	}

	// Verify response is nil when error is returned
	if resp != nil {
		t.Errorf("Expected nil response when error is returned, got: %v", resp)
	}
}

// TestTokenTransport_Auth_Failure_403Forbidden tests that auth() returns error on 403
func TestTokenTransport_Auth_Failure_403Forbidden(t *testing.T) {
	authServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		w.Write([]byte(`{"errors":[{"code":"FORBIDDEN","message":"access denied"}]}`))
	}))
	t.Cleanup(authServer.Close)

	transport := &TokenTransport{
		Transport: http.DefaultTransport,
		Username:  "testuser",
		Password:  "testpass",
	}

	authService := &authService{
		Realm:   authServer.URL,
		Service: "test-service",
		Scope:   "repository:test/repo:pull",
	}

	token, resp, err := transport.auth(authService)

	if err == nil {
		t.Fatal("Expected error for 403 status, got nil")
	}

	httpErr, ok := err.(*HttpStatusError)
	if !ok {
		t.Fatalf("Expected *HttpStatusError, got: %T", err)
	}

	if httpErr.Response.StatusCode != http.StatusForbidden {
		t.Errorf("Expected status 403, got: %d", httpErr.Response.StatusCode)
	}

	if token != "" {
		t.Errorf("Expected empty token, got: %q", token)
	}

	if resp != nil {
		t.Errorf("Expected nil response when error is returned, got: %v", resp)
	}
}

// TestTokenTransport_Auth_Failure_500ServerError tests that auth() returns error on 500
func TestTokenTransport_Auth_Failure_500ServerError(t *testing.T) {
	authServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte(`Internal Server Error`))
	}))
	t.Cleanup(authServer.Close)

	transport := &TokenTransport{
		Transport: http.DefaultTransport,
		Username:  "testuser",
		Password:  "testpass",
	}

	authService := &authService{
		Realm:   authServer.URL,
		Service: "test-service",
		Scope:   "repository:test/repo:pull",
	}

	token, resp, err := transport.auth(authService)

	if err == nil {
		t.Fatal("Expected error for 500 status, got nil")
	}

	httpErr, ok := err.(*HttpStatusError)
	if !ok {
		t.Fatalf("Expected *HttpStatusError, got: %T", err)
	}

	if httpErr.Response.StatusCode != http.StatusInternalServerError {
		t.Errorf("Expected status 500, got: %d", httpErr.Response.StatusCode)
	}

	if token != "" {
		t.Errorf("Expected empty token, got: %q", token)
	}

	if resp != nil {
		t.Errorf("Expected nil response when error is returned, got: %v", resp)
	}
}

// TestTokenTransport_Auth_MalformedJSON tests handling of invalid JSON response
func TestTokenTransport_Auth_MalformedJSON(t *testing.T) {
	authServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{invalid json`))
	}))
	t.Cleanup(authServer.Close)

	transport := &TokenTransport{
		Transport: http.DefaultTransport,
		Username:  "testuser",
		Password:  "testpass",
	}

	authService := &authService{
		Realm:   authServer.URL,
		Service: "test-service",
		Scope:   "repository:test/repo:pull",
	}

	token, resp, err := transport.auth(authService)

	if err == nil {
		t.Fatal("Expected JSON decode error, got nil")
	}

	if token != "" {
		t.Errorf("Expected empty token, got: %q", token)
	}

	if resp != nil {
		t.Errorf("Expected nil response when error is returned, got: %v", resp)
	}
}

// TestTokenTransport_Auth_MissingTokenField tests handling of valid JSON without token field
func TestTokenTransport_Auth_MissingTokenField(t *testing.T) {
	authServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"other_field": "value"}`))
	}))
	t.Cleanup(authServer.Close)

	transport := &TokenTransport{
		Transport: http.DefaultTransport,
		Username:  "testuser",
		Password:  "testpass",
	}

	authService := &authService{
		Realm:   authServer.URL,
		Service: "test-service",
		Scope:   "repository:test/repo:pull",
	}

	token, resp, err := transport.auth(authService)

	// This is valid - some registries may return empty token
	if err != nil {
		t.Fatalf("Expected no error, got: %v", err)
	}

	if resp != nil {
		t.Errorf("Expected nil response, got: %v", resp)
	}

	if token != "" {
		t.Errorf("Expected empty token, got: %q", token)
	}
}

// TestTokenTransport_RoundTrip_AuthFailure tests end-to-end behavior when auth fails (CRITICAL END-TO-END TEST)
func TestTokenTransport_RoundTrip_AuthFailure(t *testing.T) {
	// Mock auth server that returns 401 (simulating bad credentials)
	authServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		w.Write([]byte(`unauthorized`))
	}))
	t.Cleanup(authServer.Close)

	// Mock registry server that requires authentication
	registryServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("WWW-Authenticate", fmt.Sprintf(`Bearer realm="%s",service="test-service"`, authServer.URL))
		w.WriteHeader(http.StatusUnauthorized)
		w.Write([]byte(`authentication required`))
	}))
	t.Cleanup(registryServer.Close)

	transport := &TokenTransport{
		Transport: http.DefaultTransport,
		Username:  "baduser",
		Password:  "badpass",
	}

	req, err := http.NewRequest("GET", registryServer.URL+"/v2/test/manifests/latest", nil)
	if err != nil {
		t.Fatalf("Failed to create request: %v", err)
	}

	resp, err := transport.RoundTrip(req)

	// CRITICAL: Error must be returned (not nil)
	if err == nil {
		t.Fatal("Expected error when auth fails, got nil")
	}

	// Verify it's an HttpStatusError from the auth failure
	httpErr, ok := err.(*HttpStatusError)
	if !ok {
		t.Fatalf("Expected *HttpStatusError, got: %T", err)
	}

	// Verify it's a 401 from the auth server
	if httpErr.Response.StatusCode != http.StatusUnauthorized {
		t.Errorf("Expected status 401, got: %d", httpErr.Response.StatusCode)
	}

	// Response should be nil when error is returned
	if resp != nil {
		t.Errorf("Expected nil response when error is returned, got: %v", resp)
	}
}

// TestTokenTransport_RoundTrip_AuthSuccess tests end-to-end behavior when auth succeeds
func TestTokenTransport_RoundTrip_AuthSuccess(t *testing.T) {
	// Mock auth server that returns valid token
	authServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"token": "valid-token-789"}`))
	}))
	t.Cleanup(authServer.Close)

	// Mock registry server that requires authentication, then accepts token
	requestCount := 0
	registryServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestCount++
		authHeader := r.Header.Get("Authorization")

		if authHeader == "" {
			// First request without token - challenge for authentication
			w.Header().Set("WWW-Authenticate", fmt.Sprintf(`Bearer realm="%s",service="test-service"`, authServer.URL))
			w.WriteHeader(http.StatusUnauthorized)
			w.Write([]byte(`authentication required`))
			return
		}

		if authHeader == "Bearer valid-token-789" {
			// Second request with valid token - success
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(`{"success": true}`))
			return
		}

		// Invalid token
		w.WriteHeader(http.StatusUnauthorized)
		w.Write([]byte(`invalid token`))
	}))
	t.Cleanup(registryServer.Close)

	transport := &TokenTransport{
		Transport: http.DefaultTransport,
		Username:  "testuser",
		Password:  "testpass",
	}

	req, err := http.NewRequest("GET", registryServer.URL+"/v2/test/manifests/latest", nil)
	if err != nil {
		t.Fatalf("Failed to create request: %v", err)
	}

	resp, err := transport.RoundTrip(req)

	if err != nil {
		t.Fatalf("Expected no error, got: %v", err)
	}

	if resp.StatusCode != http.StatusOK {
		t.Errorf("Expected status 200, got: %d", resp.StatusCode)
	}

	if requestCount != 2 {
		t.Errorf("Expected 2 requests (initial + retry with token), got: %d", requestCount)
	}

	// Verify token is stored
	if transport.GetToken() != "valid-token-789" {
		t.Errorf("Expected stored token 'valid-token-789', got: %q", transport.GetToken())
	}
}

// TestTokenTransport_GetToken tests the GetToken() method
func TestTokenTransport_GetToken(t *testing.T) {
	transport := &TokenTransport{
		Transport: http.DefaultTransport,
		token:     "test-token",
	}

	token := transport.GetToken()
	if token != "test-token" {
		t.Errorf("Expected token 'test-token', got: %q", token)
	}

	// Test empty token
	transport.token = ""
	token = transport.GetToken()
	if token != "" {
		t.Errorf("Expected empty token, got: %q", token)
	}
}
