package gatekeeper

import (
	"context"

	apiv1 "github.com/slaskawi/vault-poc/api/v1"
	"github.com/slaskawi/vault-poc/pkg/barrier"
	"github.com/slaskawi/vault-poc/pkg/barrier/encryption"
)

// InitializeBarrier will attempt to initialize the underlying barrier and provide the unseal keys along with a gatekeeper token, if requested.
// Parts is the number of sharded unseal keys to generate.
// Threshold is the number of sharded keys required to reconstruct the gatekeeper key.
// Parts and threshold must be between 2 and 256.
// Returns uneal keys and the access key.
func (g *Gatekeeper) InitializeBarrier(ctx context.Context, parts int, threshold int) ([]string, string, error) {
	initialized, err := g.b.IsInitialized(ctx)
	if err != nil {
		return nil, "", err
	}
	if initialized {
		return nil, "", barrier.ErrBarrierAlreadyInitialized
	}

	gatekeeperKey, err := encryption.GenerateKey(apiv1.CipherType_AES256_GCM)
	if err != nil {
		return nil, "", err
	}

	unsealKeys, err := g.GenerateUnsealKeys(gatekeeperKey, parts, threshold)
	if err != nil {
		return nil, "", err
	}

	var accessKey string
	err = g.b.Initialize(ctx, gatekeeperKey, func() error {
		accessKey, err = g.generateAccessKey(ctx)
		return err
	})

	if err != nil {
		return nil, "", err
	}

	return unsealKeys, accessKey, nil
}
