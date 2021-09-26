// Package gatekeeper manages the supported methods for obtaining a gatekeeper key that is used to unseal the barrier.
package gatekeeper

import (
	"fmt"

	"github.com/slaskawi/vault-poc/pkg/auth"
	"github.com/slaskawi/vault-poc/pkg/barrier"
	"github.com/slaskawi/vault-poc/pkg/secret/kv"
	"github.com/slaskawi/vault-poc/pkg/storage"
)

const (
	gatekeeperPrefix       = "/kstash/gatekeeper/"
	gatekeeperTokensPrefix = gatekeeperPrefix + "/tokens/"
	accessKeyHashKey       = gatekeeperPrefix + "accessKeyHash"
)

var (
	ErrInvalidAccessKey       = fmt.Errorf("invalid access key")
	ErrInvalidAccessToken     = fmt.Errorf("invalid access token")
	ErrInvalidGatekeeperToken = fmt.Errorf("invalid gatekeeper token")
	ErrInvalidUnsealKey       = fmt.Errorf("invalid unseal key(s)")
)

// Gatekeeper object.
type Gatekeeper struct {
	store storage.Storage
	am    *auth.ACLManager
	b     *barrier.Barrier
	kv    *kv.KV
	tm    *auth.TokenManager
}

// NewGatekeeper creates a new Gatekeeper object.
func NewGatekeeper(store storage.Storage, barrier *barrier.Barrier) (*Gatekeeper, error) {
	g := &Gatekeeper{
		store: store,
		am:    auth.NewACLManager(),
		b:     barrier,
		kv:    kv.NewKV(barrier),
		tm:    auth.NewTokenManager(barrier),
	}

	return g, nil
}

// ACLManager returns the underlying ACLManager object.
func (g *Gatekeeper) ACLManager() *auth.ACLManager {
	return g.am
}

// Barrier returns the underlying Barrier object.
func (g *Gatekeeper) Barrier() *barrier.Barrier {
	return g.b
}

// KV returns the underlying KV object.
func (g *Gatekeeper) KV() *kv.KV {
	return g.kv
}

// TokenManager returns the underlying TokenManager object.
func (g *Gatekeeper) TokenManager() *auth.TokenManager {
	return g.tm
}
