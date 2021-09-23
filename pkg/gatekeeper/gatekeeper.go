// Package gatekeeper manages the supported methods for obtaining a gatekeeper key that is used to unseal the barrier.
package gatekeeper

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"fmt"

	apiv1 "github.com/slaskawi/vault-poc/api/v1"
	"github.com/slaskawi/vault-poc/pkg/barrier"
	"github.com/slaskawi/vault-poc/pkg/barrier/encryption"
	"github.com/slaskawi/vault-poc/pkg/gatekeeper/shamir"
	"github.com/slaskawi/vault-poc/pkg/storage/backend"
)

const (
	gatekeeperPrefix = "kstash/gatekeeper/"
	shamirInfo
)

var ErrInvalidGatekeeperToken = fmt.Errorf("invalid gatekeeper token")

// Gatekeeper object.
type Gatekeeper struct {
	back backend.Storage
	b    *barrier.Barrier
}

// NewGatekeeper creates a new Gatekeeper object.
func NewGatekeeper(backend backend.Storage, barrier *barrier.Barrier) (*Gatekeeper, error) {
	g := &Gatekeeper{back: backend, b: barrier}

	return g, nil
}

// Barrier returns the underlying Barrier object.
func (g *Gatekeeper) Barrier() *barrier.Barrier {
	return g.b
}

// GenerateGatekeeperTokenFromUnsealKeys generates a gatekeeper token that allows for unsealing without exposing the underlying gatekeeper key.
// NOTE: Gatekeeper tokens should be considered secrets and should be used, rotated, or revoked as soon as possible.
func (g *Gatekeeper) GenerateGatekeeperTokenFromUnsealKeys(ctx context.Context, keys []string) (string, error) {
	gatekeeperKey, err := g.gatekeeperKeyFromUnsealKeys(keys)
	if err != nil {
		return "", err
	}

	return g.GenerateGatekeeperToken(ctx, gatekeeperKey)
}

// GenerateGatekeeperToken generates a gatekeeper token that allows for unsealing without exposing the underlying gatekeeper key.
// NOTE: Gatekeeper tokens should be considered secrets and should be used, rotated, or revoked as soon as possible.
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

	if err := g.back.Put(ctx, item); err != nil {
		return "", err
	}

	return randomKeyUin64String, nil
}

// UnsealWithGatekeeperToken attempts to unseal the underlying Barrier object using a generated gatekeeper token.
// The token can only be used successfully once, unless explicitly renewed as part of this operation.
// NOTE: Gatekeeper tokens should be considered secrets and should be used, rotated, or revoked as soon as possible.
func (g *Gatekeeper) UnsealWithGatekeeperToken(ctx context.Context, gatekeeperToken string, renew bool) error {
	if sealed, err := g.b.IsSealed(ctx); err != nil {
		return err
	} else if !sealed {
		return barrier.ErrBarrierUnsealed
	}

	gatekeeperKey, err := g.gatekeeperKeyFromToken(ctx, gatekeeperToken)
	if err != nil {
		return err
	}

	if !renew {
		defer g.RevokeGatekeeperToken(ctx, gatekeeperToken)
	}

	return g.b.Unseal(ctx, gatekeeperKey)
}

// SealWithGatekeeperToken seals the barrier by validating the given gatekeeper token.
// The token can only be used successfully once, unless explicitly renewed as part of this operation.
// NOTE: Gatekeeper tokens should be considered secrets and should be used, rotated, or revoked as soon as possible.
func (g *Gatekeeper) SealWithGatekeeperToken(ctx context.Context, gatekeeperToken string, renew bool) error {
	_, err := g.gatekeeperKeyFromToken(ctx, gatekeeperToken)
	if err != nil {
		return err
	}

	if !renew {
		defer g.RevokeGatekeeperToken(ctx, gatekeeperToken)
	}

	g.b.Seal()
	return nil
}

// RotateEncryptionKeyWithGatekeeperToken attempts to rotate the active encryption key using a generated gatekeeper token.
// The token can only be used successfully once, but you can request a new one be generated as part of this process.
// NOTE: Gatekeeper tokens should be considered secrets and should be used, rotated, or revoked as soon as possible.
func (g *Gatekeeper) RotateEncryptionKeyWithGatekeeperToken(ctx context.Context, gatekeeperToken string, renew bool) error {
	gatekeeperKey, err := g.gatekeeperKeyFromToken(ctx, gatekeeperToken)
	if err != nil {
		return err
	}

	if !renew {
		defer g.RevokeGatekeeperToken(ctx, gatekeeperToken)
	}

	return g.b.RotateEncryptionKey(ctx, gatekeeperKey)
}

// RotateGatekeerToken will revoke the given gatekeeper token and generate a new one. This helps prevent long-lived tokens.
// NOTE: Gatekeeper tokens should be considered secrets and should be used, rotated, or revoked as soon as possible.
func (g *Gatekeeper) RotateGatekeerToken(ctx context.Context, gatekeeperToken string) (string, error) {
	gatekeeperKey, err := g.gatekeeperKeyFromToken(ctx, gatekeeperToken)
	if err != nil {
		return "", err
	}

	defer g.RevokeGatekeeperToken(ctx, gatekeeperToken)
	return g.GenerateGatekeeperToken(ctx, gatekeeperKey)
}

// RevokeGatekeeperToken revokes a gatekeeper token to prevent its successful use.
func (g *Gatekeeper) RevokeGatekeeperToken(ctx context.Context, gatekeeperToken string) error {
	return g.back.Delete(ctx, gatekeeperPrefix+gatekeeperToken)
}

// RevokeAllGatekeeperTokens revokes all gatekeeper tokens.
func (g *Gatekeeper) RevokeAllGatekeeperTokens(ctx context.Context) error {
	tokens, err := g.back.List(ctx, gatekeeperPrefix)
	if err != nil {
		return err
	}

	for _, token := range tokens {
		if err := g.back.Delete(ctx, gatekeeperPrefix+token); err != nil {
			return err
		}
	}

	return nil
}

// InitializeBarrier will attempt to initialize the underlying barrier and provide the unseal keys along with a gatekeeper token, if requested.
// Parts is the number of sharded unseal keys to generate.
// Threshold is the number of sharded keys required to reconstruct the gatekeeper key.
// Parts and threshold must be between 2 and 256.
// If gatekeeperToken is true, a new gatekeeper token will also be returned alongside the unseal keys.
func (g *Gatekeeper) InitializeBarrier(ctx context.Context, parts int, threshold int) ([]string, error) {
	initialized, err := g.b.IsInitialized(ctx)
	if err != nil {
		return nil, err
	}
	if initialized {
		return nil, barrier.ErrBarrierAlreadyInitialized
	}

	gatekeeperKey, err := encryption.GenerateKey(apiv1.CipherType_AES256_GCM)
	if err != nil {
		return nil, err
	}

	err = g.b.Initialize(ctx, gatekeeperKey)
	if err != nil {
		return nil, err
	}

	unsealKeys, err := g.GenerateShardedKeys(gatekeeperKey, parts, threshold)
	if err != nil {
		return nil, err
	}

	return unsealKeys, err
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
		keys = append(keys, base64.RawStdEncoding.EncodeToString(kb))
	}

	return keys, nil
}

// RotateShardedKeys generates a new set of unseal keys, replacing the existing keys, and revoking any existing gatekeeper tokens.
func (g *Gatekeeper) RotateShardedKeys(ctx context.Context, keys []string, parts int, threshold int) ([]string, error) {
	gatekeeperKey, err := g.gatekeeperKeyFromUnsealKeys(keys)
	if err != nil {
		return nil, err
	}

	defer g.RevokeAllGatekeeperTokens(ctx)
	return g.GenerateShardedKeys(gatekeeperKey, parts, threshold)
}

// UnsealWithShardedKeys combines sharded unseal keys to reconstruct the gatekeeper key and attempt to unseal the barrier.
func (g *Gatekeeper) UnsealWithShardedKeys(ctx context.Context, keys []string) error {
	gatekeeperKey, err := g.gatekeeperKeyFromUnsealKeys(keys)
	if err != nil {
		return err
	}

	return g.b.Unseal(ctx, gatekeeperKey)
}

func (g *Gatekeeper) gatekeeperKeyFromToken(ctx context.Context, gatekeeperToken string) ([]byte, error) {
	if initialized, err := g.b.IsInitialized(ctx); err != nil {
		return nil, err
	} else if !initialized {
		return nil, barrier.ErrBarrierNotInitialized
	}

	item, err := g.back.Get(ctx, gatekeeperPrefix+gatekeeperToken)
	if err != nil {
		if backend.IsErrNotFound(err) {
			return nil, ErrInvalidGatekeeperToken
		}
		return nil, err
	}

	barrierID, err := g.b.ID(context.Background())
	if err != nil {
		return nil, err
	}

	keyString := gatekeeperToken[:18] + barrierID.Uint64String() + gatekeeperPrefix
	keyHash := sha256.Sum256([]byte(keyString))
	gatekeeperKey, err := encryption.Decrypt(apiv1.CipherType_AES256_GCM, keyHash[:32], item.Val)
	if err != nil {
		return nil, err
	}

	return gatekeeperKey, nil
}

func (g *Gatekeeper) gatekeeperKeyFromUnsealKeys(keys []string) ([]byte, error) {
	keyBytes := [][]byte{}
	for _, key := range keys {
		kb, err := base64.RawStdEncoding.DecodeString(key)
		if err != nil {
			return nil, err
		}

		keyBytes = append(keyBytes, kb)
	}

	return shamir.Combine(keyBytes)
}
