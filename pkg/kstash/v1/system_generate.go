package v1

import (
	"context"

	apiv1 "github.com/slaskawi/vault-poc/api/v1"
)

// SystemGenerateAccessToken generates a new AccessToken from the given access key.
func (s *KStash) SystemGenerateAccessToken(ctx context.Context, req *apiv1.SystemGenerateAccessTokenRequest) (*apiv1.SystemGenerateAccessTokenResponse, error) {
	resp := &apiv1.SystemGenerateAccessTokenResponse{}
	token, err := s.gk.NewToken()
	if err != nil {
		return nil, err
	}

	token.Acls = req.Acls
	token.EnabledAt = req.EnabledAt
	token.ExpiresAt = req.ExpiresAt
	token.Metadata = req.Metadata
	token.Namespace = req.Namespace

	resp.Token = token
	err = s.gk.SaveAccessTokenWithAccessKey(ctx, req.AccessKey, resp.Token)
	return resp, err
}

// SystemGenerateGatekeeperToken generates a new gatekeeper token from unseal keys.
func (s *KStash) SystemGenerateGatekeeperToken(ctx context.Context, req *apiv1.SystemGenerateGatekeeperTokenRequest) (*apiv1.SystemGenerateGatekeeperTokenResponse, error) {
	var err error
	resp := &apiv1.SystemGenerateGatekeeperTokenResponse{}
	resp.GatekeeperToken, err = s.gk.GenerateGatekeeperTokenFromUnsealKeys(ctx, req.UnsealKeys)
	return resp, err
}
