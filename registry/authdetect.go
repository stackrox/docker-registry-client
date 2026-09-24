package registry

import (
	"io"
	"net/http"
)

type authType int

const (
	authTypeUnknown authType = iota
	authTypeBasic
	authTypeBearer
)

// detectAuthType makes an unauthenticated request to /v2/ and inspects the
// WWW-Authenticate challenge to determine whether the registry uses bearer
// token or basic authentication.
func detectAuthType(transport http.RoundTripper, registryURL string) authType {
	req, err := http.NewRequest("GET", registryURL+"/v2/", nil)
	if err != nil {
		return authTypeUnknown
	}

	resp, err := transport.RoundTrip(req)
	if err != nil {
		return authTypeUnknown
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, resp.Body)

	if resp.StatusCode != http.StatusUnauthorized {
		return authTypeUnknown
	}

	challenges := parseAuthHeader(resp.Header)
	for _, c := range challenges {
		switch c.Scheme {
		case "bearer":
			return authTypeBearer
		case "basic":
			return authTypeBasic
		}
	}

	return authTypeUnknown
}

// baseTransport wraps an http.RoundTripper to satisfy the Transport interface
// when no token-based authentication is needed.
type baseTransport struct {
	http.RoundTripper
}

func (t *baseTransport) GetToken() string { return "" }

// WrapTransportWithDetection probes the registry's /v2/ endpoint per the
// Docker Distribution spec to determine the required authentication scheme,
// then builds a transport that uses only that scheme. Falls back to the full
// stack (both basic and token) if detection fails.
func WrapTransportWithDetection(transport http.RoundTripper, url, username, password string) Transport {
	at := detectAuthType(transport, url)
	return wrapForAuthType(transport, url, username, password, at)
}

func wrapForAuthType(transport http.RoundTripper, url, username, password string, at authType) Transport {
	switch at {
	case authTypeBearer:
		tokenTransport := &TokenTransport{
			Transport: transport,
			Username:  username,
			Password:  password,
		}
		return &ErrorTransport{Transport: tokenTransport}
	case authTypeBasic:
		basicTransport := &BasicTransport{
			Transport: &baseTransport{transport},
			URL:       url,
			Username:  username,
			Password:  password,
		}
		return &ErrorTransport{Transport: basicTransport}
	default:
		return WrapTransport(transport, url, username, password)
	}
}
