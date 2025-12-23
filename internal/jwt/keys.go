package jwt

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"sync"
	"time"
)

type Key struct {
	ID         string
	PrivateKey *rsa.PrivateKey
	PublicKey  *rsa.PublicKey
	CreatedAt  time.Time
}

type KeyStore struct {
	mu     sync.RWMutex
	keys   map[string]*Key
	curr   *Key
	maxAge time.Duration
}

func NewKeyStore(maxAge time.Duration) *KeyStore {
	ks := &KeyStore{
		keys:   make(map[string]*Key),
		maxAge: maxAge,
	}
	ks.Rotate()
	return ks
}

func (ks *KeyStore) Rotate() {
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	kid := randomID()

	k := &Key{
		ID:         kid,
		PrivateKey: key,
		PublicKey:  &key.PublicKey,
		CreatedAt:  time.Now(),
	}

	ks.mu.Lock()
	defer ks.mu.Unlock()
	ks.keys[kid] = k
	ks.curr = k

	ks.pruneOldKeys()
}

func (ks *KeyStore) pruneOldKeys() {
	if ks.maxAge == 0 {
		return
	}

	cutoff := time.Now().Add(-ks.maxAge)
	for id, key := range ks.keys {
		if key.CreatedAt.Before(cutoff) && key != ks.curr {
			delete(ks.keys, id)
		}
	}
}

func (ks *KeyStore) Current() *Key {
	ks.mu.RLock()
	defer ks.mu.RUnlock()
	return ks.curr
}

func (ks *KeyStore) AllPublic() []*Key {
	ks.mu.RLock()
	defer ks.mu.RUnlock()
	out := make([]*Key, 0, len(ks.keys))
	for _, k := range ks.keys {
		out = append(out, k)
	}
	return out
}

func randomID() string {
	b := make([]byte, 16)
	rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}
