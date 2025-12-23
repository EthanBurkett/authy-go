package jwt

import "github.com/golang-jwt/jwt/v5"

type CustomClaims struct {
	jwt.RegisteredClaims
	Data map[string]any `json:"data,omitempty"`
}
