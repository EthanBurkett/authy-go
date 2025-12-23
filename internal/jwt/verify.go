package jwt

import (
	"errors"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

func VerifyToken(tokenStr string, keyFunc jwt.Keyfunc, issuer, audience string) (*CustomClaims, error) {
	parser := jwt.NewParser(
		jwt.WithValidMethods([]string{"RS256"}),
		jwt.WithAudience(audience),
		jwt.WithIssuer(issuer),
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
