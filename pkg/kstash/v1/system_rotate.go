package v1

import (
	"context"

	apiv1 "github.com/slaskawi/vault-poc/api/v1"
)

// SystemRotateAccessKey rotates the access key with the current access key.
func (s *KStash) SystemRotateAccessKey(ctx context.Context, req *apiv1.SystemRotateAccessKeyRequest) (*apiv1.SystemRotateAccessKeyResponse, error) {
	var err error
	resp := &apiv1.SystemRotateAccessKeyResponse{}

	resp.AccessKey, err = s.gk.RotateAccessKey(ctx, req.AccessKey)
	return resp, err
}

// SystemRotateEncryptionKey rotates the encryption key with a valid gatekeeper token.
func (s *KStash) SystemRotateEncryptionKey(ctx context.Context, req *apiv1.SystemRotateEncryptionKeyRequest) (*apiv1.SystemRotateEncryptionKeyResponse, error) {
	resp := &apiv1.SystemRotateEncryptionKeyResponse{}
	return resp, s.gk.RotateEncryptionKeyWithGatekeeperToken(ctx, req.GatekeeperToken, req.Renew)
}

// SystemRotateGatekeeperToken generates a new gatekeeper token with an existing, valid gatekeeper token.
func (s *KStash) SystemRotateGatekeeperToken(ctx context.Context, req *apiv1.SystemRotateGatekeeperTokenRequest) (*apiv1.SystemRotateGatekeeperTokenResponse, error) {
	var err error
	resp := &apiv1.SystemRotateGatekeeperTokenResponse{}
	resp.GatekeeperToken, err = s.gk.RotateGatekeeperToken(ctx, req.GatekeeperToken)
	return resp, err
}

// SystemRotateUnsealKeys generates new unseal keys with a valid set of existing unseal keys.
func (s *KStash) SystemRotateUnsealKeys(ctx context.Context, req *apiv1.SystemRotateUnsealKeysRequest) (*apiv1.SystemRotateUnsealKeysResponse, error) {
	var err error
	resp := &apiv1.SystemRotateUnsealKeysResponse{}
	resp.UnsealKeys, err = s.gk.RotateUnsealKeys(ctx, req.UnsealKeys, int(req.NumUnsealKeys), int(req.UnsealKeyThreshold))
	return resp, err
}
