package v1

import (
	"github.com/go-logr/logr"

	apiv1 "github.com/slaskawi/vault-poc/api/v1"
	"github.com/slaskawi/vault-poc/pkg/config"
	"github.com/slaskawi/vault-poc/pkg/gatekeeper"
)

type KStash struct {
	log logr.Logger
	gk  *gatekeeper.Gatekeeper

	apiv1.UnimplementedKStashServer
}

func NewKStash(log logr.Logger, conf *config.Config) (apiv1.KStashServer, error) {
	gk, err := conf.Gatekeeper(log)
	if err != nil {
		return nil, err
	}

	return &KStash{
		log: log,
		gk:  gk,
	}, nil
}
