// Package gatekeeper manages the supported methods for obtaining a gatekeeper key that is used to unseal the barrier.
package gatekeeper

import (
	"context"
	"crypto/sha256"

	apiv1 "github.com/slaskawi/vault-poc/api/v1"
	"github.com/slaskawi/vault-poc/pkg/barrier"
	"github.com/slaskawi/vault-poc/pkg/barrier/encryption"
	"github.com/slaskawi/vault-poc/pkg/gatekeeper/shamir"
)

const (
	gatekeeperPrefix = "kstash/gatekeeper/"
)

// Gatekeeper object.
type Gatekeeper struct {
	b *barrier.Barrier
}

// NewGatekeeper creates a new Gatekeeper object.
func NewGatekeeper(barrier *barrier.Barrier) (*Gatekeeper, error) {
	g := &Gatekeeper{b: barrier}

	return g, nil
}

// Barrier returns the underlying Barrier object.
func (g *Gatekeeper) Barrier() *barrier.Barrier {
	return g.b
}

// GenerateGatekeeperToken generates a gatekeeper token that allows for one-time unsealing without exposing the underlying gatekeeper key.
func (g *Gatekeeper) GenerateGatekeeperToken(ctx context.Context, gatekeeperKey []byte) (string, error) {
	if initialized, err := g.b.IsInitialized(ctx); err != nil {
		return "", err
	} else if !initialized {
		return "", barrier.ErrBarrierNotInitialized
	}

	randomKey, err := encryption.GenerateKey(apiv1.CipherType_AES256_GCM)
	if err != nil {
		return "", err
	}

	randomKeyHash := encryption.FromHash(randomKey)
	randomKeyUin64String := randomKeyHash.Uint64String()
	barrierID, err := g.b.ID(context.Background())
	if err != nil {
		return "", err
	}

	keyString := randomKeyUin64String[:18] + barrierID.Uint64String() + gatekeeperPrefix
	keyHash := sha256.Sum256([]byte(keyString))
	encrypted, err := encryption.Encrypt(apiv1.CipherType_AES256_GCM, keyHash[:32], gatekeeperKey)
	if err != nil {
		return "", err
	}

	item := &apiv1.BackendItem{
		Key: gatekeeperPrefix + randomKeyHash.Uint64String(),
		Val: encrypted,
	}

	if err := g.b.Backend().Put(ctx, item); err != nil {
		return "", err
	}

	return randomKeyUin64String, nil
}

// UnsealWithGatekeeperToken attempts to unseal the underlying Barrier object using a generated gatekeeper token.
// The token can only be used to successfully unseal the barrier once.
func (g *Gatekeeper) UnsealWithGatekeeperToken(ctx context.Context, gatekeeperToken string) error {
	if sealed, err := g.b.IsSealed(ctx); err != nil {
		return err
	} else if !sealed {
		return barrier.ErrBarrierUnsealed
	}

	item, err := g.b.Backend().Get(ctx, gatekeeperPrefix+gatekeeperToken)
	if err != nil {
		return err
	}

	barrierID, err := g.b.ID(context.Background())
	if err != nil {
		return err
	}

	keyString := gatekeeperToken[:18] + barrierID.Uint64String() + gatekeeperPrefix
	keyHash := sha256.Sum256([]byte(keyString))
	gatekeeperKey, err := encryption.Decrypt(apiv1.CipherType_AES256_GCM, keyHash[:32], item.Val)
	if err != nil {
		return err
	}

	defer g.RevokeGatekeeperToken(ctx, gatekeeperToken)
	return g.b.Unseal(ctx, gatekeeperKey)
}

// RevokeGatekeeperToken revokes a gatekeeper token to prevent its successful use.
func (g *Gatekeeper) RevokeGatekeeperToken(ctx context.Context, gatekeeperToken string) error {
	return g.b.Backend().Delete(ctx, gatekeeperPrefix+gatekeeperToken)
}

// GenerateShardedKeys generates new sharded unseal keys for the gatekeeper key.
// Parts is the number of sharded keys to generate.
// Threshold is the number of sharded keys required to reconstruct the gatekeeper key.
// Parts and threshold must be between 2 and 256.
func (g *Gatekeeper) GenerateShardedKeys(gatekeeperKey []byte, parts int, threshold int) ([]string, error) {
	keyBytes, err := shamir.Split(gatekeeperKey, parts, threshold)
	if err != nil {
		return nil, err
	}

	keys := []string{}
	for _, kb := range keyBytes {
		keys = append(keys, string(kb))
	}

	return keys, nil
}

// CombineShardedKeys combines sharded unseal key to reconstruct the gatekeeper key and attempt to unseal the barrier.
func (g *Gatekeeper) CombineShardedKeys(ctx context.Context, keys []string) error {
	keyBytes := [][]byte{}
	for _, key := range keys {
		keyBytes = append(keyBytes, []byte(key))
	}

	gatekeeperKey, err := shamir.Combine(keyBytes)
	if err != nil {
		return err
	}

	return g.b.Unseal(ctx, gatekeeperKey)
}
