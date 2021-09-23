package gatekeeper

import (
	"context"
	"strings"

	apiv1 "github.com/slaskawi/vault-poc/api/v1"
	"github.com/slaskawi/vault-poc/pkg/barrier"
	"github.com/slaskawi/vault-poc/pkg/barrier/encryption"
	"github.com/slaskawi/vault-poc/pkg/storage"
)

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
	token := randomKeyHash.Base32()[:encryption.AES256GCMSize]
	keyHash, err := g.keyHashFromToken(token)
	if err != nil {
		return "", err
	}

	encrypted, err := encryption.Encrypt(apiv1.CipherType_AES256_GCM, keyHash, gatekeeperKey)
	if err != nil {
		return "", err
	}

	itemKey := itemKeyFromKeyHash(keyHash)
	item := &apiv1.BackendItem{
		Key: gatekeeperTokensPrefix + itemKey,
		Val: encrypted,
	}

	if err := g.store.Put(ctx, item); err != nil {
		return "", err
	}

	return formatToken(token), nil
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

// RotateGatekeeperToken will revoke the given gatekeeper token and generate a new one. This helps prevent long-lived tokens.
// NOTE: Gatekeeper tokens should be considered secrets and should be used, rotated, or revoked as soon as possible.
func (g *Gatekeeper) RotateGatekeeperToken(ctx context.Context, gatekeeperToken string) (string, error) {
	gatekeeperKey, err := g.gatekeeperKeyFromToken(ctx, gatekeeperToken)
	if err != nil {
		return "", err
	}

	defer g.RevokeGatekeeperToken(ctx, gatekeeperToken)
	return g.GenerateGatekeeperToken(ctx, gatekeeperKey)
}

// RevokeGatekeeperToken revokes a gatekeeper token to prevent its successful use.
func (g *Gatekeeper) RevokeGatekeeperToken(ctx context.Context, gatekeeperToken string) error {
	gatekeeperToken = strings.ReplaceAll(gatekeeperToken, "-", "")
	if len(gatekeeperToken) != encryption.AES256GCMSize {
		return ErrInvalidGatekeeperToken
	}

	keyHash, err := g.keyHashFromToken(gatekeeperToken)
	if err != nil {
		return err
	}

	itemKey := itemKeyFromKeyHash(keyHash)
	return g.store.Delete(ctx, gatekeeperTokensPrefix+itemKey)
}

// RevokeAllGatekeeperTokens revokes all gatekeeper tokens.
func (g *Gatekeeper) RevokeAllGatekeeperTokens(ctx context.Context) error {
	tokens, err := g.store.List(ctx, gatekeeperTokensPrefix)
	if err != nil {
		return err
	}

	for _, token := range tokens {
		if err := g.store.Delete(ctx, gatekeeperTokensPrefix+token); err != nil {
			return err
		}
	}

	return nil
}

func (g *Gatekeeper) gatekeeperKeyFromToken(ctx context.Context, gatekeeperToken string) ([]byte, error) {
	if initialized, err := g.b.IsInitialized(ctx); err != nil {
		return nil, err
	} else if !initialized {
		return nil, barrier.ErrBarrierNotInitialized
	}

	gatekeeperToken = strings.ReplaceAll(gatekeeperToken, "-", "")
	if len(gatekeeperToken) != encryption.AES256GCMSize {
		return nil, ErrInvalidGatekeeperToken
	}

	keyHash, err := g.keyHashFromToken(gatekeeperToken)
	if err != nil {
		return nil, err
	}

	itemKey := itemKeyFromKeyHash(keyHash)
	item, err := g.store.Get(ctx, gatekeeperTokensPrefix+itemKey)
	if err != nil {
		if storage.IsErrNotFound(err) {
			return nil, ErrInvalidGatekeeperToken
		}
		return nil, err
	}

	gatekeeperKey, err := encryption.Decrypt(apiv1.CipherType_AES256_GCM, keyHash, item.Val)
	if err != nil {
		return nil, err
	}

	return gatekeeperKey, nil
}

func (g *Gatekeeper) keyHashFromToken(token string) ([]byte, error) {
	barrierID, err := g.b.ID(context.Background())
	if err != nil {
		return nil, err
	}

	keyString := token + barrierID.Base64()
	return encryption.BytesHash(keyString)[:encryption.AES256GCMSize], nil
}

func itemKeyFromKeyHash(keyHash []byte) string {
	itemKey := encryption.FromHash(keyHash)
	return itemKey.Base32()[:10]
}

func formatToken(token string) string {
	buf := strings.Builder{}
	for i := 0; i < len(token); i += 4 {
		if i > 0 {
			buf.WriteString("-")
		}
		buf.WriteString(token[i : i+4])
	}
	return buf.String()
}
