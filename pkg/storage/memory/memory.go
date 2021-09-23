package memory

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"sync"

	apiv1 "github.com/slaskawi/vault-poc/api/v1"
	"github.com/slaskawi/vault-poc/pkg/storage"
	"google.golang.org/protobuf/proto"
)

// MemoryStorage object.
type MemoryStorage struct {
	config *MemoryConfig
	m      map[string][]byte
	mu     sync.RWMutex
}

// NewMemoryStorage returns a new MemoryStorage object.
func NewMemoryStorage(config *MemoryConfig) (storage.Storage, error) {
	if config == nil {
		config = &MemoryConfig{}
	}

	return &MemoryStorage{
		config: config,
		m:      map[string][]byte{},
	}, nil
}

// List items with keys that have the given prefix.
func (s *MemoryStorage) List(ctx context.Context, prefix string) ([]string, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if !strings.HasSuffix(prefix, "/") {
		prefix += "/"
	}

	keys := map[string]struct{}{}
	for key := range s.m {
		if strings.HasPrefix(key, prefix) {
			key = strings.TrimPrefix(key, prefix)
			if len(key) == 0 {
				continue
			}

			if i := strings.Index(key, "/"); i == -1 {
				keys[key] = struct{}{}
			} else {
				keys[key[:i+1]] = struct{}{}
			}
		}
	}

	keysList := make([]string, len(keys))
	i := 0
	for key := range keys {
		keysList[i] = key
		i++
	}

	sort.Strings(keysList)

	return keysList, nil
}

// Get an item by its key.
func (s *MemoryStorage) Get(ctx context.Context, key string) (*apiv1.BackendItem, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	b, ok := s.m[key]
	if !ok {
		return nil, fmt.Errorf("%w: %s", storage.ErrNotFound, key)
	}

	item := &apiv1.BackendItem{}
	err := proto.Unmarshal(b, item)
	return item, err
}

// Put an item in the backend.
func (s *MemoryStorage) Put(ctx context.Context, item *apiv1.BackendItem) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	b, err := proto.Marshal(item)
	if err != nil {
		return err
	}

	s.m[item.Key] = b
	return nil
}

// Delete an item from the backend.
func (s *MemoryStorage) Delete(ctx context.Context, key string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	delete(s.m, key)
	return nil
}
