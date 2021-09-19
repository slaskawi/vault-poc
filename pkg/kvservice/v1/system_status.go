package v1

import (
	"context"

	apiv1 "github.com/slaskawi/vault-poc/api/v1"
	"google.golang.org/protobuf/types/known/timestamppb"
)

func (s *KVService) SystemStatus(ctx context.Context, req *apiv1.SystemStatusRequest) (*apiv1.SystemStatusResponse, error) {
	// TODO: finish
	return &apiv1.SystemStatusResponse{
		Sealed:          true,
		ServerTimestamp: timestamppb.Now(),
	}, nil
}
