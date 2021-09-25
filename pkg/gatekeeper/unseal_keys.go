package gatekeeper

import (
	"context"
	"encoding/base64"

	apiv1 "github.com/slaskawi/vault-poc/api/v1"
	"github.com/slaskawi/vault-poc/pkg/barrier/encryption"
	"github.com/slaskawi/vault-poc/pkg/gatekeeper/shamir"
)

// GenerateUnsealKeys generates new sharded unseal keys for the gatekeeper key.
// Parts is the number of sharded keys to generate.
// Threshold is the number of sharded keys required to reconstruct the gatekeeper key.
// Parts and threshold must be between 2 and 256.
func (g *Gatekeeper) GenerateUnsealKeys(gatekeeperKey []byte, parts int, threshold int) ([]string, error) {
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

// RotateUnsealKeys generates a new set of unseal keys, rotate the gatekeeper key, and revoking any existing gatekeeper tokens.
// Parts is the number of sharded keys to generate.
// Threshold is the number of sharded keys required to reconstruct the gatekeeper key.
// Parts and threshold must be between 2 and 256.
func (g *Gatekeeper) RotateUnsealKeys(ctx context.Context, keys []string, parts int, threshold int) ([]string, error) {
	gatekeeperKey, err := g.gatekeeperKeyFromUnsealKeys(keys)
	if err != nil {
		return nil, err
	}

	if err := g.b.ValidateGatekeeperKey(ctx, gatekeeperKey); err != nil {
		return nil, ErrInvalidUnsealKey
	}

	newGatekeeperKey, err := encryption.GenerateKey(apiv1.CipherType_AES256_GCM)
	if err != nil {
		return nil, err
	}

	unsealKeys, err := g.GenerateUnsealKeys(newGatekeeperKey, parts, threshold)
	if err != nil {
		return nil, err
	}

	g.b.ChangeGatekeeperKey(ctx, newGatekeeperKey)
	defer g.RevokeAllGatekeeperTokens(ctx)
	return unsealKeys, nil
}

// UnsealWithUnsealKeys combines sharded unseal keys to reconstruct the gatekeeper key and attempt to unseal the barrier.
func (g *Gatekeeper) UnsealWithUnsealKeys(ctx context.Context, keys []string) error {
	gatekeeperKey, err := g.gatekeeperKeyFromUnsealKeys(keys)
	if err != nil {
		return err
	}

	return g.b.Unseal(ctx, gatekeeperKey)
}

func (g *Gatekeeper) gatekeeperKeyFromUnsealKeys(keys []string) ([]byte, error) {
	keyBytes := [][]byte{}
	for _, key := range keys {
		if len(key) < 42 || len(key) > 46 {
			return nil, ErrInvalidUnsealKey
		}
		kb, err := base64.RawStdEncoding.DecodeString(key)
		if err != nil {
			return nil, ErrInvalidUnsealKey
		}

		keyBytes = append(keyBytes, kb)
	}

	key, err := shamir.Combine(keyBytes)
	if err != nil {
		return nil, ErrInvalidUnsealKey
	}

	return key, nil
}
