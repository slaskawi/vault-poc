package gatekeeper

import (
	"context"

	apiv1 "github.com/slaskawi/vault-poc/api/v1"
	"github.com/slaskawi/vault-poc/pkg/barrier/encryption"
)

// RotateAccessKey rotates the access key using the existing access key.
func (g *Gatekeeper) RotateAccessKey(ctx context.Context, accessKey string) (string, error) {
	if err := g.CompareAccessKey(ctx, accessKey); err != nil {
		return "", err
	}

	return g.generateAccessKey(ctx)
}

// RotateAccessKeyWithUnsealKeys rotates the access key using the given unseal keys.
// NOTE: this functionality was removed from the API to maintain separation of concerns and prevent unseal key holders from granting themselves access tokens.
// Discussion on this is pending, but this could be removed entirely in the future.
func (g *Gatekeeper) RotateAccessKeyWithUnsealKeys(ctx context.Context, unsealKeys []string) (string, error) {
	gatekeeperKey, err := g.gatekeeperKeyFromUnsealKeys(unsealKeys)
	if err != nil {
		return "", err
	}

	if err := g.b.ValidateGatekeeperKey(ctx, gatekeeperKey); err != nil {
		return "", ErrInvalidUnsealKey
	}

	return g.generateAccessKey(ctx)
}

// NewToken generates a new access token.
func (g *Gatekeeper) NewToken() (*apiv1.AccessToken, error) {
	return g.tm.NewToken()
}

// SaveAccessTokenUsingAccessKey saves a new access token by validating the given access key.
func (g *Gatekeeper) SaveAccessTokenWithAccessKey(ctx context.Context, accessKey string, token *apiv1.AccessToken) error {
	if err := g.CompareAccessKey(ctx, accessKey); err != nil {
		return err
	}

	if err := g.am.ValidateACLs(token.Acls); err != nil {
		return err
	}

	return g.tm.SaveToken(ctx, token)
}

// CompareAccessKey compares the given access key against the known access key
func (g *Gatekeeper) CompareAccessKey(ctx context.Context, accessKey string) error {
	item, err := g.b.Get(ctx, accessKeyHashKey)
	if err != nil {
		return err
	}

	if item.Raw == nil {
		return ErrInvalidAccessKey
	}

	if string(item.Raw) != accessKey {
		return ErrInvalidAccessKey
	}

	return nil
}

func (g *Gatekeeper) generateAccessKey(ctx context.Context) (string, error) {
	accessKey, err := encryption.GenerateKey(apiv1.CipherType_AES256_GCM)
	if err != nil {
		return "", err
	}

	accessKeyHash := encryption.FromHash(accessKey)
	accessKeyStr := accessKeyHash.Base64()
	item := &apiv1.Item{
		Key: accessKeyHashKey,
		Raw: []byte(accessKeyStr),
	}

	if err := g.b.Put(ctx, item); err != nil {
		return "", err
	}

	return accessKeyStr, nil
}
