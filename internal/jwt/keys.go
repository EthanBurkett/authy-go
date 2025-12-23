package jwt

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"sync"
)

type Key struct {
	ID         string
	PrivateKey *rsa.PrivateKey
	PublicKey  *rsa.PublicKey
}

type KeyStore struct {
	mu   sync.RWMutex
	keys map[string]*Key
	curr *Key
}

func NewKeyStore() *KeyStore {
	ks := &KeyStore{
		keys: make(map[string]*Key),
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
	}

	ks.mu.Lock()
	defer ks.mu.Unlock()

	ks.keys[kid] = k
	ks.curr = k
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
	return base64.URLEncoding.EncodeToString(b)
}
