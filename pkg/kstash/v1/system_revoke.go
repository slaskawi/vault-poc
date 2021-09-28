package v1

import (
	"context"

	apiv1 "github.com/slaskawi/vault-poc/api/v1"
)

// SystemRevokeGatekeeperToken revokes a gatekeeper token.
func (s *KStash) SystemRevokeGatekeeperToken(ctx context.Context, req *apiv1.SystemRevokeGatekeeperTokenRequest) (*apiv1.SystemRevokeGatekeeperTokenResponse, error) {
	resp := &apiv1.SystemRevokeGatekeeperTokenResponse{}
	return resp, s.gk.RevokeGatekeeperToken(ctx, req.GatekeeperToken)
}
