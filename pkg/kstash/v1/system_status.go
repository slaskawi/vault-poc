package v1

import (
	"context"

	apiv1 "github.com/slaskawi/vault-poc/api/v1"
	"google.golang.org/protobuf/types/known/timestamppb"
)

func (s *KStash) SystemStatus(ctx context.Context, req *apiv1.SystemStatusRequest) (*apiv1.SystemStatusResponse, error) {
	var err error
	resp := &apiv1.SystemStatusResponse{
		Sealed:          true,
		ServerTimestamp: timestamppb.Now(),
	}

	resp.Initialized, err = s.gk.Barrier().IsInitialized(ctx)
	if err != nil {
		return nil, err
	}

	if !resp.Initialized {
		return resp, nil
	}

	resp.Sealed, err = s.gk.Barrier().IsSealed(ctx)
	return resp, err
}
