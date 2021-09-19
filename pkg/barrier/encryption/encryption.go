package encryption

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"fmt"
	"io"

	apiv1 "github.com/slaskawi/vault-poc/api/v1"
)

const (
	aes256GCMSize = 32
	nonceSize     = 12
)

// ValidateKey ensures the given key is the correct length.
func ValidateKey(cipherType apiv1.CipherType, key []byte) error {
	if key == nil {
		return fmt.Errorf("key cannot be nil")
	}

	switch cipherType {
	case apiv1.CipherType_AES256_GCM:
		if len(key) != aes256GCMSize {
			return fmt.Errorf("key must be %d bytes, not %d", aes256GCMSize, len(key))
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
		key = make([]byte, aes256GCMSize)
	default:
		return nil, fmt.Errorf("unknown cipherType: %s", cipherType.String())
	}

	if _, err := io.ReadFull(rand.Reader, key); err != nil {
		return nil, err
	}

	return key, nil
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
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, nil, err
	}

	nonce := make([]byte, nonceSize)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, nil, err
	}

	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, nil, err
	}

	return aesgcm, nonce, nil
}
