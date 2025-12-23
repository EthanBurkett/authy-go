package jwt

import (
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net/http"
)

type JWKS struct {
	Keys []JWK `json:"keys"`
}

func WriteJWKS(w http.ResponseWriter, ks *KeyStore) {
	keys := ks.AllPublic()
	jwks := JWKS{}

	for _, k := range keys {
		pub := k.PublicKey
		jwks.Keys = append(jwks.Keys, JWK{
			Kty: "RSA",
			Use: "sig",
			Alg: "RS256",
			Kid: k.ID,
			N:   base64.RawURLEncoding.EncodeToString(pub.N.Bytes()),
			E:   base64.RawURLEncoding.EncodeToString(big.NewInt(int64(pub.E)).Bytes()),
		})
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(jwks)
}
