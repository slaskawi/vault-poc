package v1

import (
	"github.com/go-logr/logr"

	apiv1 "github.com/slaskawi/vault-poc/api/v1"
)

type KStash struct {
	log logr.Logger

	apiv1.UnimplementedKStashServer
}

func NewKStash(log logr.Logger) (apiv1.KStashServer, error) {
	return &KStash{log: log}, nil
}
