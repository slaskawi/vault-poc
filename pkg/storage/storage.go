package storage

import (
	"context"
	"errors"
	"fmt"

	apiv1 "github.com/slaskawi/vault-poc/api/v1"
)

var (
	ErrNotFound = fmt.Errorf("key not found")
)

// Storage represents a physical backend storage engine.
type Storage interface {
	// List items with keys that have the given prefix.
	List(ctx context.Context, prefix string) ([]string, error)

	// Get an item by its key.
	Get(ctx context.Context, key string) (*apiv1.BackendItem, error)

	// Put an item in the backend.
	Put(ctx context.Context, item *apiv1.BackendItem) error

	// Delete an item from the backend.
	Delete(ctx context.Context, key string) error
}

// IsErrNotFound determines if the given error is ErrNotFound.
func IsErrNotFound(err error) bool {
	return errors.Is(err, ErrNotFound)
}
