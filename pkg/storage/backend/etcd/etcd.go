package etcd

import (
	"context"

	apiv1 "github.com/slaskawi/vault-poc/api/v1"
	"github.com/slaskawi/vault-poc/pkg/storage/backend"
)

// EtcdStorage object.
type EtcdStorage struct {
	config *EtcdConfig
}

// NewEtcdStorage returns a new EtcdStorage object.
func NewEtcdStorage(config *EtcdConfig) (backend.Storage, error) {
	if config == nil {
		config = &EtcdConfig{}
	}

	// TODO: finish
	return &EtcdStorage{config: config}, nil
}

// List items with keys that have the given prefix.
func (s *EtcdStorage) List(ctx context.Context, prefix string) ([]string, error) {
	panic("not implemented") // TODO: Implement
}

// Get an item by its key.
func (s *EtcdStorage) Get(ctx context.Context, key string) (*apiv1.BackendItem, error) {
	panic("not implemented") // TODO: Implement
}

// Put an item in the backend.
func (s *EtcdStorage) Put(ctx context.Context, item *apiv1.BackendItem) error {
	panic("not implemented") // TODO: Implement
}

// Delete an item from the backend.
func (s *EtcdStorage) Delete(ctx context.Context, key string) error {
	panic("not implemented") // TODO: Implement
}
