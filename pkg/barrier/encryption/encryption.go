// Package encryption provides various helpers for encryption operations.
package encryption

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"hash/fnv"
	"io"
	"sync"

	apiv1 "github.com/slaskawi/vault-poc/api/v1"
)

const (
	AES256GCMSize = 32
	nonceSize     = 12
)

type aeadCache struct {
	m  map[uint64]cipher.AEAD
	mu sync.RWMutex
}

func (c *aeadCache) Get(key uint64) cipher.AEAD {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.m[key]
}

func (c *aeadCache) Put(key uint64, aead cipher.AEAD) {
	c.mu.Lock()
	c.m[key] = aead
	c.mu.Unlock()
}

var cache = aeadCache{
	m: map[uint64]cipher.AEAD{},
}

// ValidateKey ensures the given key is the correct length.
func ValidateKey(cipherType apiv1.CipherType, key []byte) error {
	if key == nil {
		return fmt.Errorf("key cannot be nil")
	}

	switch cipherType {
	case apiv1.CipherType_AES256_GCM:
		if len(key) != AES256GCMSize {
			return fmt.Errorf("key must be %d bytes, not %d", AES256GCMSize, len(key))
		}
	default:
		return fmt.Errorf("unknown cipherType: %s", cipherType.String())
	}

	return nil
}

// GenerateKey generates a new key for the given cipherType.
func GenerateKey(cipherType apiv1.CipherType) ([]byte, error) {
	var key []byte

	switch cipherType {
	case apiv1.CipherType_AES256_GCM:
		key = make([]byte, AES256GCMSize)
	default:
		return nil, fmt.Errorf("unknown cipherType: %s", cipherType.String())
	}

	if _, err := io.ReadFull(rand.Reader, key); err != nil {
		return nil, err
	}

	return key, nil
}

// Uint64Hash generates a uint64 hash from the given byte slice.
func Uint64Hash(b []byte) uint64 {
	hash := fnv.New64a()
	hash.Write(b)
	return hash.Sum64()
}

// BytesHash generates a sha256 hash from the given string.
func BytesHash(s string) []byte {
	hash := sha256.Sum256([]byte(s))
	return hash[:]
}

// Encrypt data.
func Encrypt(cipherType apiv1.CipherType, key, data []byte) ([]byte, error) {
	if err := ValidateKey(cipherType, key); err != nil {
		return nil, err
	}

	switch cipherType {
	case apiv1.CipherType_AES256_GCM:
		aesgcm, nonce, err := newAES256GCM(key)
		if err != nil {
			return nil, err
		}

		encrypted := aesgcm.Seal(nil, nonce, data, nil)
		return append(nonce, encrypted...), nil
	default:
		return nil, fmt.Errorf("unknown cipherType: %s", cipherType.String())
	}
}

// Decrypt data.
func Decrypt(cipherType apiv1.CipherType, key, data []byte) ([]byte, error) {
	if err := ValidateKey(cipherType, key); err != nil {
		return nil, err
	}

	switch cipherType {
	case apiv1.CipherType_AES256_GCM:
		aesgcm, _, err := newAES256GCM(key)
		if err != nil {
			return nil, err
		}

		return aesgcm.Open(nil, data[:nonceSize], data[nonceSize:], nil)
	default:
		return nil, fmt.Errorf("unknown cipherType: %s", cipherType.String())
	}
}

func newAES256GCM(key []byte) (cipher.AEAD, []byte, error) {
	nonce := make([]byte, nonceSize)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, nil, err
	}

	var aesgcm cipher.AEAD
	keyHash := Uint64Hash(key)

	if aead := cache.Get(keyHash); aead != nil {
		aesgcm = aead
	} else {
		block, err := aes.NewCipher(key)
		if err != nil {
			return nil, nil, err
		}

		aesgcm, err = cipher.NewGCM(block)
		if err != nil {
			return nil, nil, err
		}

		cache.Put(keyHash, aesgcm)
	}

	return aesgcm, nonce, nil
}
