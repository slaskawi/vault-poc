package config

import (
	"fmt"
	"os"
	"strings"

	etcdclient "go.etcd.io/etcd/client/v3"

	"github.com/go-logr/logr"
	"github.com/slaskawi/vault-poc/pkg/barrier"
	"github.com/slaskawi/vault-poc/pkg/gatekeeper"
	"github.com/slaskawi/vault-poc/pkg/storage"
	"github.com/slaskawi/vault-poc/pkg/storage/etcd"
	"github.com/slaskawi/vault-poc/pkg/storage/memory"
)

// Config object.
type Config struct {
	GrpcPort       string
	RestPort       string
	StorageBackend string
	EtcdEndpoints  []string
	EtcdUsername   string
	EtcdPassword   string
}

// Get Config object from configuration file or environment variables.
func Get() *Config {
	return &Config{
		GrpcPort:       getEnv("GRPC_PORT", "8080"),
		RestPort:       getEnv("REST_PORT", "8081"),
		StorageBackend: getEnv("STORAGE_BACKEND", "memory"),
		EtcdEndpoints:  toSlice(getEnv("ETCD_ENDPOINTS", "http://127.0.0.1:2379")),
		EtcdUsername:   getEnv("ETCD_USERNAME", ""),
		EtcdPassword:   getEnv("ETCD_PASSWORD", ""),
	}
}

// Gatekeeper returns a new Gatekeeper instance from the config.
func (c *Config) Gatekeeper(log logr.Logger) (*gatekeeper.Gatekeeper, error) {
	var (
		storage storage.Storage
		err     error
	)

	switch c.StorageBackend {
	case "memory":
		storage, err = memory.NewMemoryStorage(nil)
		log.Info("WARNING: using in-memory storage backend, nothing will be persisted to disk")
	case "etcd":
		storage, err = etcd.NewEtcdStorage(&etcdclient.Config{
			Endpoints: c.EtcdEndpoints,
			Username:  c.EtcdUsername,
			Password:  c.EtcdPassword,
		})
	default:
		return nil, fmt.Errorf("unknown storage backend: %s", c.StorageBackend)
	}

	if err != nil {
		return nil, err
	}

	barr, err := barrier.NewBarrier(storage)
	if err != nil {
		return nil, err
	}

	return gatekeeper.NewGatekeeper(storage, barr)
}

func getEnv(name, ifEmpty string) string {
	val := os.Getenv(name)
	if len(val) == 0 {
		return ifEmpty
	}
	return val
}

func toSlice(val string) []string {
	return strings.Split(val, ",")
}
