package kv

import (
	"github.com/slaskawi/vault-poc/pkg/auth"
	"github.com/slaskawi/vault-poc/pkg/barrier"
)

// KV object.
type KV struct {
	b  *barrier.Barrier
	tm *auth.TokenManager
}

// NewKV creates a new KV object.
func NewKV(b *barrier.Barrier) *KV {
	return &KV{b: b, tm: auth.NewTokenManager(b)}
}
