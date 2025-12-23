package jwt

import (
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"math/big"
	"net/http"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

type JWK struct {
	Kty string `json:"kty"`
	Use string `json:"use"`
	Alg string `json:"alg"`
	Kid string `json:"kid"`
	N   string `json:"n"`
	E   string `json:"e"`
}

type JWKSCache struct {
	mu       sync.RWMutex
	keys     map[string]*rsa.PublicKey
	expires  time.Time
	jwksURL  string
	lifetime time.Duration
}

func NewJWKSCache(url string, lifetime time.Duration) *JWKSCache {
	return &JWKSCache{
		keys:     make(map[string]*rsa.PublicKey),
		jwksURL:  url,
		lifetime: lifetime,
	}
}

func (c *JWKSCache) Get(kid string) (*rsa.PublicKey, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	key, ok := c.keys[kid]
	return key, ok
}

func (c *JWKSCache) Refresh() error {
	resp, err := http.Get(c.jwksURL)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	var jwks JWKS
	if err := json.NewDecoder(resp.Body).Decode(&jwks); err != nil {
		return err
	}

	newKeys := make(map[string]*rsa.PublicKey)
	for _, key := range jwks.Keys {
		pub, err := rsaKeyFromJWK(key)
		if err != nil {
			return err
		}
		newKeys[key.Kid] = pub
	}

	c.mu.Lock()
	defer c.mu.Unlock()
	c.keys = newKeys
	c.expires = time.Now().Add(c.lifetime)
	return nil
}

func (c *JWKSCache) KeyFunc(token *jwt.Token) (any, error) {
	kid, ok := token.Header["kid"].(string)
	if !ok {
		return nil, errors.New("missing kid in token")
	}

	c.mu.RLock()
	expired := time.Now().After(c.expires)
	_, exists := c.keys[kid]
	c.mu.RUnlock()

	if expired || !exists {
		if err := c.Refresh(); err != nil {
			return nil, err
		}
	}

	c.mu.RLock()
	defer c.mu.RUnlock()
	key, ok := c.keys[kid]
	if !ok {
		return nil, errors.New("unknown kid")
	}
	return key, nil
}

func rsaKeyFromJWK(jwk JWK) (*rsa.PublicKey, error) {
	nBytes, err := base64.RawURLEncoding.DecodeString(jwk.N)
	if err != nil {
		return nil, err
	}
	eBytes, err := base64.RawURLEncoding.DecodeString(jwk.E)
	if err != nil {
		return nil, err
	}

	n := new(big.Int).SetBytes(nBytes)
	e := new(big.Int).SetBytes(eBytes).Int64()

	return &rsa.PublicKey{
		N: n,
		E: int(e),
	}, nil
}
