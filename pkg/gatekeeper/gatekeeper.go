// Package gatekeeper manages the supported methods for obtaining a gatekeeper key that is used to unseal the barrier.
package gatekeeper

import (
	"fmt"

	"github.com/slaskawi/vault-poc/pkg/barrier"
	"github.com/slaskawi/vault-poc/pkg/storage"
)

const (
	gatekeeperPrefix             = "kstash/gatekeeper/"
	gatekeeperTokensPrefix       = gatekeeperPrefix + "/tokens/"
	gatekeeperAccessTokensPrefix = gatekeeperPrefix + "/accessTokens/"
	accessKeyHashKey             = gatekeeperPrefix + "accessKeyHash"
)

var (
	ErrInvalidAccessToken     = fmt.Errorf("invalid access token")
	ErrInvalidGatekeeperToken = fmt.Errorf("invalid gatekeeper token")
	ErrInvalidUnsealKey       = fmt.Errorf("invalid unseal key(s)")
)

// Gatekeeper object.
type Gatekeeper struct {
	store storage.Storage
	b     *barrier.Barrier
}

// NewGatekeeper creates a new Gatekeeper object.
func NewGatekeeper(store storage.Storage, barrier *barrier.Barrier) (*Gatekeeper, error) {
	g := &Gatekeeper{store: store, b: barrier}

	return g, nil
}

// Barrier returns the underlying Barrier object.
func (g *Gatekeeper) Barrier() *barrier.Barrier {
	return g.b
}
