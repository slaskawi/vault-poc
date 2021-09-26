package v1

import (
	"context"
	"time"

	apiv1 "github.com/slaskawi/vault-poc/api/v1"
)

// AuthTokenLookup attempts to lookup and return information about a token from the given token ID or token reference ID. If neither are provided, a token ID is extracted from the request context.
func (s *KStash) AuthTokenLookup(ctx context.Context, req *apiv1.AuthTokenLookupRequest) (*apiv1.AuthTokenLookupResponse, error) {
	resp := &apiv1.AuthTokenLookupResponse{}

	var token *apiv1.AccessToken
	var err error

	if len(req.TokenID) > 0 {
		token, err = s.gk.TokenManager().GetToken(ctx, req.TokenID)
	} else if len(req.TokenReferenceID) > 0 {
		token, err = s.gk.TokenManager().GetTokenByReferenceID(ctx, req.TokenReferenceID)
	} else {
		token, err = s.GetToken(ctx)
	}

	if err != nil {
		return resp, err
	}

	resp.Token = token
	return resp, nil
}

// AuthTokenRenew attempts to renew the given token with a new TTL. If no TTL is provided a default of one hour is applied.
// It attempts to update the given token ID or token reference ID. If neither is provided, a token ID is extracted from the request context.
func (s *KStash) AuthTokenRenew(ctx context.Context, req *apiv1.AuthTokenRenewRequest) (*apiv1.AuthTokenRenewResponse, error) {
	resp := &apiv1.AuthTokenRenewResponse{}

	ttl := time.Hour
	if len(req.Ttl) > 0 {
		var err error
		ttl, err = s.ParseTTL(req.Ttl)
		if err != nil {
			return resp, err
		}
	}

	var token *apiv1.AccessToken
	var err error

	if len(req.TokenID) > 0 {
		token, err = s.gk.TokenManager().GetToken(ctx, req.TokenID)
	} else if len(req.TokenReferenceID) > 0 {
		token, err = s.gk.TokenManager().GetTokenByReferenceID(ctx, req.TokenReferenceID)
	} else {
		token, err = s.GetToken(ctx)
	}

	if err != nil {
		return resp, err
	}

	token.ExpiresAt = time.Now().Add(ttl).Unix()
	resp.Token = token
	return resp, s.gk.TokenManager().SaveToken(ctx, token)
}

// AuthTokenRevoke attempts to revoke a token from the given token ID or token reference ID. If neither are provided, a token ID is extracted from the request context.
func (s *KStash) AuthTokenRevoke(ctx context.Context, req *apiv1.AuthTokenRevokeRequest) (*apiv1.AuthTokenRevokeResponse, error) {
	resp := &apiv1.AuthTokenRevokeResponse{}

	if len(req.TokenID) > 0 {
		return resp, s.gk.TokenManager().RevokeToken(ctx, req.TokenID)
	} else if len(req.TokenReferenceID) > 0 {
		return resp, s.gk.TokenManager().RevokeTokenByReferenceID(ctx, req.TokenReferenceID)
	}

	tokenID, err := s.GetTokenID(ctx)
	if err != nil {
		return resp, err
	}

	return resp, s.gk.TokenManager().RevokeToken(ctx, tokenID)
}
