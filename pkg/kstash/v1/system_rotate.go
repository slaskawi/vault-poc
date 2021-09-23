package v1

import (
	"context"

	apiv1 "github.com/slaskawi/vault-poc/api/v1"
)

func (s *KStash) SystemRotateEncryptionKey(ctx context.Context, req *apiv1.SystemRotateEncryptionKeyRequest) (*apiv1.SystemRotateEncryptionKeyResponse, error) {
	resp := &apiv1.SystemRotateEncryptionKeyResponse{}
	return resp, s.gk.RotateEncryptionKeyWithGatekeeperToken(ctx, req.GatekeeperToken, req.Renew)
}

func (s *KStash) SystemRotateGatekeeperToken(ctx context.Context, req *apiv1.SystemRotateGatekeeperTokenRequest) (*apiv1.SystemRotateGatekeeperTokenResponse, error) {
	var err error
	resp := &apiv1.SystemRotateGatekeeperTokenResponse{}
	resp.GatekeeperToken, err = s.gk.RotateGatekeeperToken(ctx, req.GatekeeperToken)
	return resp, err
}

func (s *KStash) SystemRotateUnsealKeys(ctx context.Context, req *apiv1.SystemRotateUnsealKeysRequest) (*apiv1.SystemRotateUnsealKeysResponse, error) {
	var err error
	resp := &apiv1.SystemRotateUnsealKeysResponse{}
	resp.UnsealKeys, err = s.gk.RotateUnsealKeys(ctx, req.UnsealKeys, int(req.NumUnsealKeys), int(req.UnsealKeyThreshold))
	return resp, err
}
