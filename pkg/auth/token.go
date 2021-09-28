package auth

import (
	"context"
	"time"

	apiv1 "github.com/slaskawi/vault-poc/api/v1"
	"github.com/slaskawi/vault-poc/pkg/barrier"
	"github.com/slaskawi/vault-poc/pkg/barrier/encryption"
	"github.com/slaskawi/vault-poc/pkg/storage"
	"google.golang.org/protobuf/proto"
)

// TokenManager object.
type TokenManager struct {
	b *barrier.Barrier
}

// NewTokenManager returns a new TokenManager.
func NewTokenManager(b *barrier.Barrier) *TokenManager {
	return &TokenManager{b: b}
}

// NewToken creates and initializes a token's fields and generates IDs for it.
func (t *TokenManager) NewToken() (*apiv1.AccessToken, error) {
	bs, err := encryption.GenerateKey(apiv1.CipherType_AES256_GCM)
	if err != nil {
		return nil, err
	}

	hash := encryption.FromHash(bs[:13])
	token := &apiv1.AccessToken{
		Id:          tokenIDPrefix + hash.Base64(),
		ReferenceID: tokenReferenceIDPrefix + hash.Uint64String()[:TokenLength-len(tokenReferenceIDPrefix)],
		CreatedAt:   time.Now().Unix(),
		Acls:        []*apiv1.ACL{},
		Metadata:    map[string]string{},
	}

	return token, nil
}

// IsTokenValid returns an error if the token is invalid.
func (t *TokenManager) IsTokenValid(token *apiv1.AccessToken) error {
	now := time.Now()

	enabled := time.Unix(token.EnabledAt, 0)
	if now.Before(enabled) {
		return ErrTokenNotActiveYet
	}

	expires := time.Unix(token.ExpiresAt, 0)
	if now.After(expires) {
		return ErrTokenNotFound
	}

	return nil
}

// SaveToken saves a token to the barrier.
func (t *TokenManager) SaveToken(ctx context.Context, token *apiv1.AccessToken) error {
	if len(token.Id) != TokenLength {
		return ErrTokenInvalid
	}
	if len(token.ReferenceID) < TokenLength {
		return ErrTokenInvalid
	}

	if token.ExpiresAt <= 0 {
		token.ExpiresAt = time.Now().Add(TokenDefaultTTL).Unix()
	}

	bs, err := proto.Marshal(token)
	if err != nil {
		return err
	}

	item := &apiv1.Item{
		Key: authTokensPrefix + token.ReferenceID,
		Raw: bs,
	}

	return t.b.Put(ctx, item)
}

// GetToken gets a token by its ID.
func (t *TokenManager) GetToken(ctx context.Context, id string) (*apiv1.AccessToken, error) {
	if len(id) != TokenLength {
		return nil, ErrTokenInvalid
	}

	return t.GetTokenByReferenceID(ctx, getTokenReferenceIDFromID(id))
}

// GetTokenByReferenceID gets a token by its reference ID. Returns an error if token is invalid.
func (t *TokenManager) GetTokenByReferenceID(ctx context.Context, referenceID string) (*apiv1.AccessToken, error) {
	if len(referenceID) != TokenLength {
		return nil, ErrTokenInvalid
	}

	item, err := t.b.Get(ctx, authTokensPrefix+referenceID)
	if err != nil {
		if storage.IsErrNotFound(err) {
			return nil, ErrTokenNotFound
		}
		return nil, err
	}

	token := &apiv1.AccessToken{}
	if err := proto.Unmarshal(item.Raw, token); err != nil {
		return nil, err
	}

	return token, t.IsTokenValid(token)
}

// RevokeToken immediately deletes a token.
func (t *TokenManager) RevokeToken(ctx context.Context, id string) error {
	if len(id) != TokenLength {
		return ErrTokenInvalid
	}

	refID := getTokenReferenceIDFromID(id)
	return t.RevokeTokenByReferenceID(ctx, refID)
}

// RevokeTokenByReferenceID immediately deletes a token by its reference ID.
func (t *TokenManager) RevokeTokenByReferenceID(ctx context.Context, referenceID string) error {
	if len(referenceID) != TokenLength {
		return ErrTokenInvalid
	}

	return t.b.Delete(ctx, authTokensPrefix+referenceID)
}

// RenewToken renews a token as long as it is still valid.
func (t *TokenManager) RenewToken(ctx context.Context, id string, newTTL time.Duration) (*apiv1.AccessToken, error) {
	if len(id) != TokenLength {
		return nil, ErrTokenInvalid
	}

	refID := getTokenReferenceIDFromID(id)
	return t.RenewTokenByReferenceID(ctx, refID, newTTL)
}

// RenewToken renews a token by its reference ID as long as it's still valid.
func (t *TokenManager) RenewTokenByReferenceID(ctx context.Context, referenceID string, newTTL time.Duration) (*apiv1.AccessToken, error) {
	if len(referenceID) != TokenLength {
		return nil, ErrTokenInvalid
	}

	mu, err := t.b.LockKey(ctx, authTokensPrefix+referenceID)
	if err != nil {
		if storage.IsErrNotFound(err) {
			return nil, ErrTokenNotFound
		}
		return nil, err
	}

	if err := mu.Lock(); err != nil {
		return nil, err
	}
	defer mu.Unlock()

	token, err := t.GetTokenByReferenceID(ctx, referenceID)
	if err != nil {
		return nil, err
	}

	token.ExpiresAt = time.Now().Add(newTTL).Unix()

	if err := t.SaveToken(ctx, token); err != nil {
		return nil, err
	}

	return token, nil
}

// PruneExpiredTokens removes all expired tokens from storage.
func (t *TokenManager) PruneExpiredTokens(ctx context.Context) error {
	tokens, err := t.b.List(ctx, authTokensPrefix)
	if err != nil {
		return err
	}

	for _, ref := range tokens {
		_, err := t.GetTokenByReferenceID(ctx, ref)
		if err == ErrTokenNotFound {
			t.RevokeTokenByReferenceID(ctx, ref)
		}
	}

	return nil
}

func getTokenReferenceIDFromID(id string) string {
	hash := encryption.FromBase64(id[len(tokenIDPrefix):])
	return tokenReferenceIDPrefix + hash.Uint64String()[:TokenLength-len(tokenReferenceIDPrefix)]
}
