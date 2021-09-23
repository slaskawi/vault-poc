package v1

import (
	"context"

	apiv1 "github.com/slaskawi/vault-poc/api/v1"
)

func (s *KStash) SystemGenerateGatekeeperToken(ctx context.Context, req *apiv1.SystemGenerateGatekeeperTokenRequest) (*apiv1.SystemGenerateGatekeeperTokenResponse, error) {
	var err error
	resp := &apiv1.SystemGenerateGatekeeperTokenResponse{}
	resp.GatekeeperToken, err = s.gk.GenerateGatekeeperTokenFromUnsealKeys(ctx, req.UnsealKeys)
	return resp, err
}
