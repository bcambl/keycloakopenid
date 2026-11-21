package keycloakopenid

import (
	"context"
	"crypto/tls"
	"errors"
	"io"
	"net/http"
	"net/url"
	"time"
)

const (
	upstreamTimeout     = 10 * time.Second
	maxUpstreamResponse = 1 << 20 // 1 MiB
)

var errResponseTooLarge = errors.New("upstream response exceeds 1 MiB limit")

// newUpstreamHTTPClient returns a client for talking to Keycloak. Requests are
// bounded by a 10-second timeout, redirects are refused, and response bodies
// are capped at 1 MiB.
func newUpstreamHTTPClient(insecureSkipVerify bool) *http.Client {
	base := &http.Transport{
		Proxy:                 http.ProxyFromEnvironment,
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          100,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: time.Second,
		TLSClientConfig:       &tls.Config{InsecureSkipVerify: insecureSkipVerify},
	}
	return &http.Client{
		Transport: &boundedRoundTripper{base: base},
		Timeout:   upstreamTimeout,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}

type boundedRoundTripper struct {
	base http.RoundTripper
}

func (b *boundedRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	resp, err := b.base.RoundTrip(req)
	if err != nil {
		return nil, err
	}
	resp.Body = &limitedReadCloser{rc: resp.Body, remaining: maxUpstreamResponse}
	return resp, nil
}

type limitedReadCloser struct {
	rc        io.ReadCloser
	remaining int64
}

func (l *limitedReadCloser) Read(p []byte) (int, error) {
	if l.remaining <= 0 {
		var probe [1]byte
		n, err := l.rc.Read(probe[:])
		if n > 0 || err == nil {
			return 0, errResponseTooLarge
		}
		return 0, err
	}
	if int64(len(p)) > l.remaining {
		p = p[:l.remaining]
	}
	n, err := l.rc.Read(p)
	l.remaining -= int64(n)
	return n, err
}

func (l *limitedReadCloser) Close() error {
	return l.rc.Close()
}

// setKeycloakCompatURL probes a couple of well-known endpoints to determine if
// the current Keycloak instance is the older wildfly or the newer quarkus
// version and dynamically adds /auth to the URL as required.
func setKeycloakCompatURL(ctx context.Context, client *http.Client, keycloakURL *url.URL, realm string) (*url.URL, error) {
	if ok, err := endpointReachable(ctx, client, keycloakURL.JoinPath("realms", realm)); err != nil {
		return nil, err
	} else if ok {
		return keycloakURL, nil
	}

	if ok, err := endpointReachable(ctx, client, keycloakURL.JoinPath("auth", "realms", realm)); err != nil {
		return nil, err
	} else if ok {
		return keycloakURL.JoinPath("auth"), nil
	}

	return nil, errors.New("could not determine Keycloak compatibility")
}

func endpointReachable(ctx context.Context, client *http.Client, target *url.URL) (bool, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, target.String(), nil)
	if err != nil {
		return false, err
	}
	resp, err := client.Do(req)
	if err != nil {
		return false, err
	}
	defer func() { _ = resp.Body.Close() }()
	return resp.StatusCode == http.StatusOK, nil
}
