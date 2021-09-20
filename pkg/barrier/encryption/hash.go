package encryption

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"hash/fnv"
	"strconv"
)

// Hash wraps a byte slice with functions to generate hashed representations of the byte slice.
type Hash struct {
	b []byte
}

// Sha256 creates a new Hash object by performing a SHA-256 hash on the given byte slice.
func Sha256(b []byte) Hash {
	hash := sha256.Sum256(b)
	return Hash{b: hash[:]}
}

// FromHash creates a new Hash object from the result of hash operation.
func FromHash(b []byte) Hash {
	return Hash{b: b}
}

// Uint64 returns an FNV-1a representation of the byte slice.
func (h *Hash) Uint64() uint64 {
	hash := fnv.New64a()
	hash.Write(h.b)
	return hash.Sum64()
}

// Uint64String returns a string representation of the FNV-1a hash.
func (h *Hash) Uint64String() string {
	return strconv.FormatUint(h.Uint64(), 10)
}

// Base64 returns a base64-encoded string representation of the byte slice.
func (h *Hash) Base64() string {
	return base64.RawStdEncoding.EncodeToString(h.b)
}

// Hex returns a hex-encoded string representation of the byte slice.
func (h *Hash) Hex() string {
	return hex.EncodeToString(h.b)
}
