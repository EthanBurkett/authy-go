package jwt

import (
	"errors"
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

type JWTService struct {
	ks     *KeyStore
	config JWTConfig
}

type JWTConfig struct {
	Issuer         string
	Audience       string
	ExpiryDuration time.Duration
}

var reservedKeys = map[string]struct{}{
	"iss": {}, "aud": {}, "sub": {}, "exp": {}, "nbf": {},
	"iat": {}, "jti": {}, "kid": {}, "alg": {}, "typ": {},
}

func NewJWTService(ks *KeyStore, cfg JWTConfig) *JWTService {
	return &JWTService{
		ks:     ks,
		config: cfg,
	}
}

func validateUserData(data map[string]any) error {
	for k := range data {
		if _, exists := reservedKeys[k]; exists {
			return fmt.Errorf("reserved claim key used: %s", k)
		}
	}
	return nil
}

func (s *JWTService) IssueToken(userID string, userData map[string]any) (string, error) {
	if err := validateUserData(userData); err != nil {
		return "", err
	}

	key := s.ks.Current()
	claims := CustomClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:  userID,
			Issuer:   s.config.Issuer,
			Audience: []string{s.config.Audience},
			IssuedAt: jwt.NewNumericDate(time.Now()),
			ExpiresAt: jwt.NewNumericDate(
				time.Now().Add(s.config.ExpiryDuration),
			),
		},
		Data: userData,
	}

	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	token.Header["kid"] = key.ID

	return token.SignedString(key.PrivateKey)
}

func (s *JWTService) VerifyToken(tokenStr string, keyFunc jwt.Keyfunc) (*CustomClaims, error) {
	parser := jwt.NewParser(
		jwt.WithValidMethods([]string{"RS256"}),
		jwt.WithAudience(s.config.Audience),
		jwt.WithIssuer(s.config.Issuer),
		jwt.WithLeeway(30*time.Second),
	)

	token, err := parser.ParseWithClaims(tokenStr, &CustomClaims{}, keyFunc)
	if err != nil {
		return nil, err
	}

	claims, ok := token.Claims.(*CustomClaims)
	if !ok || !token.Valid {
		return nil, errors.New("invalid token")
	}

	return claims, nil
}
