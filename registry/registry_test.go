package registry

import (
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
)

func TestDetectAuthType_Bearer(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("WWW-Authenticate", `Bearer realm="https://auth.example.com/token",service="registry"`)
		w.WriteHeader(http.StatusUnauthorized)
	}))
	t.Cleanup(srv.Close)

	if got := detectAuthType(http.DefaultTransport, srv.URL); got != authTypeBearer {
		t.Errorf("detectAuthType = %d, want authTypeBearer", got)
	}
}

func TestDetectAuthType_Basic(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("WWW-Authenticate", `Basic realm="Registry"`)
		w.WriteHeader(http.StatusUnauthorized)
	}))
	t.Cleanup(srv.Close)

	if got := detectAuthType(http.DefaultTransport, srv.URL); got != authTypeBasic {
		t.Errorf("detectAuthType = %d, want authTypeBasic", got)
	}
}

func TestDetectAuthType_NoChallenge(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(srv.Close)

	if got := detectAuthType(http.DefaultTransport, srv.URL); got != authTypeUnknown {
		t.Errorf("detectAuthType = %d, want authTypeUnknown", got)
	}
}

func TestDetectAuthType_Unreachable(t *testing.T) {
	transport := &http.Transport{
		DialContext: (&net.Dialer{Timeout: 100 * time.Millisecond}).DialContext,
	}
	if got := detectAuthType(transport, "http://192.0.2.1:1"); got != authTypeUnknown {
		t.Errorf("detectAuthType = %d, want authTypeUnknown", got)
	}
}

func TestWrapTransport_ChainStructure(t *testing.T) {
	transport := WrapTransport(http.DefaultTransport, "http://example.com", "user", "pass")

	et := transport.(*ErrorTransport)
	bt := et.Transport.(*BasicTransport)
	_, ok := bt.Transport.(*TokenTransport)
	if !ok {
		t.Fatalf("expected ErrorTransport → BasicTransport → TokenTransport chain")
	}
}

func TestWrapTransportWithDetection_BearerChain(t *testing.T) {
	var srv *httptest.Server
	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("WWW-Authenticate",
			fmt.Sprintf(`Bearer realm="%s/token",service="test"`, srv.URL))
		w.WriteHeader(http.StatusUnauthorized)
	}))
	t.Cleanup(srv.Close)

	transport := WrapTransportWithDetection(http.DefaultTransport, srv.URL, "user", "pass")
	et := transport.(*ErrorTransport)
	_, ok := et.Transport.(*TokenTransport)
	if !ok {
		t.Fatalf("bearer-detected: expected ErrorTransport → TokenTransport, got %T", et.Transport)
	}
}

func TestWrapTransportWithDetection_BasicChain(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("WWW-Authenticate", `Basic realm="Registry"`)
		w.WriteHeader(http.StatusUnauthorized)
	}))
	t.Cleanup(srv.Close)

	transport := WrapTransportWithDetection(http.DefaultTransport, srv.URL, "user", "pass")
	et := transport.(*ErrorTransport)
	_, ok := et.Transport.(*BasicTransport)
	if !ok {
		t.Fatalf("basic-detected: expected ErrorTransport → BasicTransport, got %T", et.Transport)
	}
}

func TestWrapTransportWithDetection_FallbackChain(t *testing.T) {
	base := &http.Transport{
		DialContext: (&net.Dialer{Timeout: 100 * time.Millisecond}).DialContext,
	}
	transport := WrapTransportWithDetection(base, "http://192.0.2.1:1", "user", "pass")

	et := transport.(*ErrorTransport)
	bt := et.Transport.(*BasicTransport)
	_, ok := bt.Transport.(*TokenTransport)
	if !ok {
		t.Fatalf("fallback: expected full chain ErrorTransport → BasicTransport → TokenTransport")
	}
}

func TestBearerAuth_NoBasicHeadersSentToRegistry(t *testing.T) {
	var basicAuthOnRegistryEndpoints atomic.Int32

	var srv *httptest.Server
	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		auth := r.Header.Get("Authorization")

		if r.URL.Path != "/token" && len(auth) > 5 && auth[:5] == "Basic" {
			basicAuthOnRegistryEndpoints.Add(1)
		}

		switch r.URL.Path {
		case "/v2/":
			if auth == "" {
				w.Header().Set("WWW-Authenticate",
					fmt.Sprintf(`Bearer realm="%s/token",service="test"`, srv.URL))
				w.WriteHeader(http.StatusUnauthorized)
				return
			}
			w.WriteHeader(http.StatusOK)

		case "/token":
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(authToken{Token: "good-token"})

		default:
			if auth == "Bearer good-token" {
				w.WriteHeader(http.StatusOK)
				w.Write([]byte(`{}`))
				return
			}
			w.Header().Set("WWW-Authenticate",
				fmt.Sprintf(`Bearer realm="%s/token",service="test"`, srv.URL))
			w.WriteHeader(http.StatusUnauthorized)
		}
	}))
	t.Cleanup(srv.Close)

	transport := WrapTransportWithDetection(http.DefaultTransport, srv.URL, "user", "pass")
	client := &http.Client{Transport: transport}

	for i := 0; i < 3; i++ {
		resp, err := client.Get(srv.URL + fmt.Sprintf("/v2/repo%d/manifests/latest", i))
		if err != nil {
			t.Fatalf("request %d failed: %v", i, err)
		}
		resp.Body.Close()
	}

	if got := basicAuthOnRegistryEndpoints.Load(); got != 0 {
		t.Errorf("Basic auth header sent %d times to registry endpoints; want 0", got)
	}
}

func TestBasicAuth_NoTokenEndpointHit(t *testing.T) {
	var tokenEndpointHit atomic.Int32

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/token" {
			tokenEndpointHit.Add(1)
			w.WriteHeader(http.StatusOK)
			return
		}
		_, _, hasBasic := r.BasicAuth()
		if !hasBasic {
			w.Header().Set("WWW-Authenticate", `Basic realm="Registry"`)
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{}`))
	}))
	t.Cleanup(srv.Close)

	transport := WrapTransportWithDetection(http.DefaultTransport, srv.URL, "user", "pass")
	client := &http.Client{Transport: transport}

	resp, err := client.Get(srv.URL + "/v2/repo/manifests/latest")
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}

	if got := tokenEndpointHit.Load(); got != 0 {
		t.Errorf("token endpoint hit %d times, want 0 for basic-only registry", got)
	}
}

func TestTokenTransport_AuthFailureReturnsError(t *testing.T) {
	var srv *httptest.Server
	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/token" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}

		w.Header().Set("WWW-Authenticate",
			fmt.Sprintf(`Bearer realm="%s/token",service="test-registry"`, srv.URL))
		w.WriteHeader(http.StatusUnauthorized)
	}))
	t.Cleanup(srv.Close)

	transport := &TokenTransport{
		Transport: http.DefaultTransport,
		Username:  "user",
		Password:  "pass",
	}

	client := &http.Client{Transport: transport}

	_, err := client.Get(srv.URL + "/v2/repo/manifests/latest")
	if err == nil {
		t.Fatal("expected error when token endpoint returns 401, got nil")
	}
}

func TestTokenTransport_SuccessfulReauth(t *testing.T) {
	var tokenVersion atomic.Int32
	tokenVersion.Store(1)

	var srv *httptest.Server
	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/token" {
			newToken := fmt.Sprintf("token-v%d", tokenVersion.Load())
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(authToken{Token: newToken})
			return
		}

		auth := r.Header.Get("Authorization")
		expected := fmt.Sprintf("Bearer token-v%d", tokenVersion.Load())

		if auth == expected {
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(`{}`))
			return
		}

		w.Header().Set("WWW-Authenticate",
			fmt.Sprintf(`Bearer realm="%s/token",service="test-registry"`, srv.URL))
		w.WriteHeader(http.StatusUnauthorized)
	}))
	t.Cleanup(srv.Close)

	transport := &TokenTransport{
		Transport: http.DefaultTransport,
		Username:  "user",
		Password:  "pass",
	}

	client := &http.Client{Transport: transport}

	resp, err := client.Get(srv.URL + "/v2/repo/manifests/latest")
	if err != nil {
		t.Fatalf("first request failed: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("first request: got status %d, want 200", resp.StatusCode)
	}
	if got := transport.GetToken(); got != "token-v1" {
		t.Errorf("cached token = %q, want %q", got, "token-v1")
	}
}
