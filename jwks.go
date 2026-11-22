package keycloakopenid

import (
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"math/big"
	"net/http"
	"strings"
	"sync"

	"github.com/golang-jwt/jwt/v5"
)

type jwksCache struct {
	client *http.Client
	url    string

	mu   sync.Mutex
	keys map[string]jwkKey
}

type jwkKey struct {
	publicKey any
	algorithm string
}

type jwkJSON struct {
	KeyType   string `json:"kty"`
	KeyID     string `json:"kid"`
	Algorithm string `json:"alg"`
	Use       string `json:"use"`
	Curve     string `json:"crv"`
	N         string `json:"n"`
	E         string `json:"e"`
	X         string `json:"x"`
	Y         string `json:"y"`
}

func (c *jwksCache) verificationKey(ctx context.Context, token *jwt.Token) (any, error) {
	kid, ok := token.Header["kid"].(string)
	if !ok || kid == "" {
		return nil, errors.New("oidc: id token missing key id")
	}
	return c.key(ctx, kid, token.Method.Alg())
}

func (c *jwksCache) key(ctx context.Context, kid, alg string) (any, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if key, ok := c.keys[kid]; ok {
		return key.forAlgorithm(alg)
	}
	if err := c.fetchLocked(ctx); err != nil {
		return nil, err
	}
	key, ok := c.keys[kid]
	if !ok {
		return nil, errors.New("oidc: id token key not found")
	}
	return key.forAlgorithm(alg)
}

func (k jwkKey) forAlgorithm(alg string) (any, error) {
	if k.algorithm != "" && k.algorithm != alg {
		return nil, errors.New("oidc: key algorithm mismatch")
	}

	valid := false
	switch key := k.publicKey.(type) {
	case *rsa.PublicKey:
		valid = strings.HasPrefix(alg, "RS") || strings.HasPrefix(alg, "PS")
	case *ecdsa.PublicKey:
		valid = alg == ecdsaAlgorithm(key.Curve)
	case ed25519.PublicKey:
		valid = alg == "EdDSA"
	}
	if !valid || !asymmetricSigningAlgs[alg] {
		return nil, errors.New("oidc: key algorithm mismatch")
	}
	return k.publicKey, nil
}

func ecdsaAlgorithm(curve elliptic.Curve) string {
	switch curve {
	case elliptic.P256():
		return "ES256"
	case elliptic.P384():
		return "ES384"
	case elliptic.P521():
		return "ES512"
	default:
		return ""
	}
}

func (c *jwksCache) fetchLocked(ctx context.Context) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.url, nil)
	if err != nil {
		return errors.New("oidc: invalid jwks endpoint")
	}
	resp, err := c.client.Do(req)
	if err != nil {
		return errors.New("oidc: jwks unavailable")
	}
	defer func() { _ = resp.Body.Close() }()

	body, err := io.ReadAll(io.LimitReader(resp.Body, maxUpstreamResponse+1))
	if err != nil || len(body) > maxUpstreamResponse {
		return errors.New("oidc: invalid jwks response")
	}
	if resp.StatusCode != http.StatusOK {
		return errors.New("oidc: jwks unavailable")
	}

	keys, err := parseJWKS(body)
	if err != nil {
		return err
	}
	c.keys = keys
	return nil
}

func parseJWKS(body []byte) (map[string]jwkKey, error) {
	var doc struct {
		Keys []jwkJSON `json:"keys"`
	}
	if err := json.Unmarshal(body, &doc); err != nil || len(doc.Keys) == 0 {
		return nil, errors.New("oidc: malformed jwks response")
	}

	keys := make(map[string]jwkKey)
	for _, raw := range doc.Keys {
		if raw.Use != "" && raw.Use != "sig" {
			continue
		}
		if raw.KeyType != "RSA" && raw.KeyType != "EC" && raw.KeyType != "OKP" {
			continue
		}
		if raw.KeyID == "" {
			return nil, errors.New("oidc: jwks key missing key id")
		}
		if _, exists := keys[raw.KeyID]; exists {
			return nil, errors.New("oidc: jwks contains duplicate key id")
		}
		publicKey, err := raw.publicKey()
		if err != nil {
			return nil, err
		}
		keys[raw.KeyID] = jwkKey{publicKey: publicKey, algorithm: raw.Algorithm}
	}
	if len(keys) == 0 {
		return nil, errors.New("oidc: jwks contains no signing keys")
	}
	return keys, nil
}

func (k jwkJSON) publicKey() (any, error) {
	switch k.KeyType {
	case "RSA":
		return k.rsaPublicKey()
	case "EC":
		return k.ecdsaPublicKey()
	case "OKP":
		return k.ed25519PublicKey()
	default:
		return nil, errors.New("oidc: unsupported jwks key type")
	}
}

func (k jwkJSON) rsaPublicKey() (*rsa.PublicKey, error) {
	n, err := decodeJWKInteger(k.N)
	if err != nil || n.Sign() <= 0 {
		return nil, errors.New("oidc: invalid RSA jwks key")
	}
	e, err := decodeJWKInteger(k.E)
	if err != nil || !e.IsInt64() {
		return nil, errors.New("oidc: invalid RSA jwks key")
	}
	exponent := e.Int64()
	if exponent < 3 || exponent > 1<<31-1 || exponent%2 == 0 {
		return nil, errors.New("oidc: invalid RSA jwks key")
	}
	return &rsa.PublicKey{N: n, E: int(exponent)}, nil
}

func (k jwkJSON) ecdsaPublicKey() (*ecdsa.PublicKey, error) {
	var curve elliptic.Curve
	switch k.Curve {
	case "P-256":
		curve = elliptic.P256()
	case "P-384":
		curve = elliptic.P384()
	case "P-521":
		curve = elliptic.P521()
	default:
		return nil, errors.New("oidc: unsupported ECDSA jwks curve")
	}
	x, err := base64.RawURLEncoding.DecodeString(k.X)
	if err != nil {
		return nil, errors.New("oidc: invalid ECDSA jwks key")
	}
	y, err := base64.RawURLEncoding.DecodeString(k.Y)
	if err != nil {
		return nil, errors.New("oidc: invalid ECDSA jwks key")
	}
	size := (curve.Params().BitSize + 7) / 8
	if len(x) != size || len(y) != size {
		return nil, errors.New("oidc: invalid ECDSA jwks key")
	}
	xInt := new(big.Int).SetBytes(x)
	yInt := new(big.Int).SetBytes(y)
	prime := curve.Params().P
	if xInt.Sign() < 0 || yInt.Sign() < 0 || xInt.Cmp(prime) >= 0 || yInt.Cmp(prime) >= 0 {
		return nil, errors.New("oidc: invalid ECDSA jwks key")
	}
	if !curve.IsOnCurve(xInt, yInt) { //nolint:staticcheck // Traefik Yaegi compatibility.
		return nil, errors.New("oidc: invalid ECDSA jwks key")
	}
	return &ecdsa.PublicKey{Curve: curve, X: xInt, Y: yInt}, nil //nolint:staticcheck // Traefik Yaegi compatibility.
}

func (k jwkJSON) ed25519PublicKey() (ed25519.PublicKey, error) {
	if k.Curve != "Ed25519" {
		return nil, errors.New("oidc: unsupported Ed25519 jwks curve")
	}
	key, err := base64.RawURLEncoding.DecodeString(k.X)
	if err != nil || len(key) != ed25519.PublicKeySize {
		return nil, errors.New("oidc: invalid Ed25519 jwks key")
	}
	return ed25519.PublicKey(key), nil
}

func decodeJWKInteger(raw string) (*big.Int, error) {
	decoded, err := base64.RawURLEncoding.DecodeString(raw)
	if err != nil || len(decoded) == 0 {
		return nil, errors.New("oidc: invalid jwks integer")
	}
	return new(big.Int).SetBytes(decoded), nil
}
