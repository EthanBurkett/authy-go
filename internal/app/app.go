package app

import (
	"log"
	"net/http"
	"time"

	"github.com/ethanburkett/authy/internal/config"
	"github.com/ethanburkett/authy/internal/jwt"
)

func New() {
	// Load config
	cfg, err := config.Load("configs/config.local.yaml")
	if err != nil {
		log.Fatalf("failed to load config: %v", err)
	}

	// Initialize KeyStore and JWT service
	ks := jwt.NewKeyStore()
	jwtService := jwt.NewJWTService(ks, jwt.JWTConfig{
		Issuer:         cfg.JWT.Issuer,
		Audience:       cfg.JWT.Audience,
		ExpiryDuration: cfg.JWT.ExpiryDuration,
	})

	jwksCache := jwt.NewJWKSCache("http://localhost:8080/.well-known/jwks.json", 5*time.Minute)

	http.HandleFunc("/login", func(w http.ResponseWriter, r *http.Request) {
		userData := map[string]interface{}{
			"role":  "admin",
			"orgId": "org_123",
			"plan":  "pro",
		}

		token, err := jwtService.IssueToken("user_123", userData)
		if err != nil {
			http.Error(w, "Failed to issue token", http.StatusInternalServerError)
			return
		}

		w.Header().Set("Content-Type", "text/plain")
		w.Write([]byte(token))
	})

	http.HandleFunc("/.well-known/jwks.json", func(w http.ResponseWriter, r *http.Request) {
		jwt.WriteJWKS(w, ks)
	})

	http.HandleFunc("/verify", func(w http.ResponseWriter, r *http.Request) {
		tokenStr := r.Header.Get("Authorization")
		if tokenStr == "" {
			http.Error(w, "Missing Authorization header", http.StatusUnauthorized)
			return
		}

		if len(tokenStr) > 7 && tokenStr[:7] == "Bearer " {
			tokenStr = tokenStr[7:]
		}

		claims, err := jwtService.VerifyToken(tokenStr, jwksCache.KeyFunc)
		if err != nil {
			http.Error(w, "Invalid token: "+err.Error(), http.StatusUnauthorized)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"sub":"` + claims.Subject + `"}`))
	})

	log.Println("Auth server running on :8080")
	if err := http.ListenAndServe(":8080", nil); err != nil {
		log.Fatalf("server failed: %v", err)
	}
}
