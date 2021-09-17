package v1

import (
	"context"

	"github.com/go-logr/logr"
	apiv1 "github.com/slaskawi/vault-poc/api/v1"
)

type KVService struct {
	log logr.Logger

	apiv1.UnimplementedKVServiceServer
}

func NewKVService(log logr.Logger) (apiv1.KVServiceServer, error) {
	return &KVService{log: log}, nil
}

func (s *KVService) Ping(ctx context.Context, req *apiv1.PingRequest) (*apiv1.PingResponse, error) {
	return &apiv1.PingResponse{Ping: "OK"}, nil
}
