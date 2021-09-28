package v1

import (
	"context"

	apiv1 "github.com/slaskawi/vault-poc/api/v1"
)

// SystemPruneTokens removes all expired access tokens from storage.
func (s *KStash) SystemPruneTokens(ctx context.Context, req *apiv1.SystemPruneTokensRequest) (*apiv1.SystemPruneTokensResponse, error) {
	resp := &apiv1.SystemPruneTokensResponse{}

	if err := s.gk.CompareAccessKey(ctx, req.AccessKey); err != nil {
		return resp, err
	}

	return resp, s.gk.TokenManager().PruneExpiredTokens(ctx)
}
