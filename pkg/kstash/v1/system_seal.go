package v1

import (
	"context"
	"fmt"

	apiv1 "github.com/slaskawi/vault-poc/api/v1"
)

func (s *KStash) SystemInitialize(ctx context.Context, req *apiv1.SystemInitializeRequest) (*apiv1.SystemInitializeResponse, error) {
	if req.NumUnsealKeys == 0 && req.UnsealKeyThreshold == 0 {
		req.NumUnsealKeys = 5
		req.UnsealKeyThreshold = 3
	}

	var err error
	resp := &apiv1.SystemInitializeResponse{}
	resp.UnsealKeys, err = s.gk.InitializeBarrier(ctx, int(req.NumUnsealKeys), int(req.UnsealKeyThreshold))
	if err != nil {
		return nil, err
	}

	if req.GenerateGatekeeperToken {
		resp.GatekeeperToken, err = s.gk.GenerateGatekeeperTokenFromUnsealKeys(ctx, resp.UnsealKeys)
	}

	return resp, err
}

func (s *KStash) SystemSeal(ctx context.Context, req *apiv1.SystemSealRequest) (*apiv1.SystemSealResponse, error) {
	resp := &apiv1.SystemSealResponse{Sealed: true}
	return resp, s.gk.SealWithGatekeeperToken(ctx, req.GatekeeperToken, req.Renew)
}

func (s *KStash) SystemUnseal(ctx context.Context, req *apiv1.SystemUnsealRequest) (*apiv1.SystemUnsealResponse, error) {
	resp := &apiv1.SystemUnsealResponse{Sealed: false}

	if len(req.GatekeeperToken) > 0 {
		return resp, s.gk.UnsealWithGatekeeperToken(ctx, req.GatekeeperToken, req.RenewGatekeeperToken)
	}

	if req.UnsealKeys == nil || len(req.UnsealKeys) < 2 || len(req.UnsealKeys) > 255 {
		return resp, fmt.Errorf("must provide at least 2 unseal keys")
	}

	return resp, s.gk.UnsealWithShardedKeys(ctx, req.UnsealKeys)
}
