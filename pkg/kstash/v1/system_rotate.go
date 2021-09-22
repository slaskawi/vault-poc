package v1

import (
	"context"

	apiv1 "github.com/slaskawi/vault-poc/api/v1"
)

func (s *KStash) SystemRotate(ctx context.Context, req *apiv1.SystemRotateRequest) (*apiv1.SystemRotateResponse, error) {
	// TODO: finish
	return &apiv1.SystemRotateResponse{
		KeyID: 0,
	}, nil
}
