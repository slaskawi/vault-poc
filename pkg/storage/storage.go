package storage

import (
	"context"
	"errors"
	"fmt"

	apiv1 "github.com/slaskawi/vault-poc/api/v1"
)

type Capability uint8

func (c Capability) Has(cap Capability) bool {
	return c&cap != 0
}

const (
	CapabilityNone Capability = 1 << iota
	CapabilityDistributedLocking
	CapabilityWatching
)

var (
	ErrNotFound = fmt.Errorf("key not found")
	ErrLocked   = fmt.Errorf("key is locked")
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

	// Capabilities determines the additional capabilities of the backend.
	Capabilities() Capability

	// LockKey locks a key with a distributed Mutex.
	LockKey(ctx context.Context, key string) (Mutex, error)
}

// Mutex represents a distributed lock at the physical backend storage engine.
type Mutex interface {
	// Lock a key.
	Lock() error

	// Unlock a key.
	Unlock() error

	// Get value of the key.
	Get() (*apiv1.BackendItem, error)
}

// IsErrNotFound determines if the given error is ErrNotFound.
func IsErrNotFound(err error) bool {
	return errors.Is(err, ErrNotFound)
}
