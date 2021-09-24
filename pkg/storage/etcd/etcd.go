package etcd

import (
	"context"
	"fmt"
	"sort"
	"strings"

	etcdclient "go.etcd.io/etcd/client/v3"
	"go.etcd.io/etcd/client/v3/concurrency"
	"google.golang.org/protobuf/proto"

	apiv1 "github.com/slaskawi/vault-poc/api/v1"
	"github.com/slaskawi/vault-poc/pkg/storage"
)

// EtcdStorage object.
type EtcdStorage struct {
	c *etcdclient.Client
}

// NewEtcdStorage returns a new EtcdStorage object.
func NewEtcdStorage(config *etcdclient.Config) (storage.Storage, error) {
	if config == nil {
		config = &etcdclient.Config{
			Endpoints: []string{"http://127.0.0.1:2379"},
		}
	}

	c, err := etcdclient.New(*config)
	if err != nil {
		return nil, err
	}

	return &EtcdStorage{
		c: c,
	}, nil
}

// List items with keys that have the given prefix.
func (s *EtcdStorage) List(ctx context.Context, prefix string) ([]string, error) {
	if !strings.HasSuffix(prefix, "/") {
		prefix += "/"
	}

	resp, err := s.c.Get(ctx, prefix, etcdclient.WithPrefix())
	if err != nil {
		return nil, err
	}

	keys := map[string]struct{}{}
	for _, kv := range resp.Kvs {
		key := string(kv.Key)

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
func (s *EtcdStorage) Get(ctx context.Context, key string) (*apiv1.BackendItem, error) {
	resp, err := s.c.Get(ctx, key)
	if err != nil {
		return nil, err
	}

	if resp == nil || resp.Kvs == nil || len(resp.Kvs) == 0 {
		return nil, storage.ErrNotFound
	}
	if len(resp.Kvs) > 1 {
		return nil, fmt.Errorf("unexpected number of keys from Etcd")
	}

	item := &apiv1.BackendItem{}
	err = proto.Unmarshal(resp.Kvs[0].Value, item)
	return item, err
}

// Put an item in the backend.
func (s *EtcdStorage) Put(ctx context.Context, item *apiv1.BackendItem) error {
	b, err := proto.Marshal(item)
	if err != nil {
		return err
	}

	_, err = s.c.Put(ctx, item.Key, string(b))
	return err
}

// Delete an item from the backend.
func (s *EtcdStorage) Delete(ctx context.Context, key string) error {
	_, err := s.c.Delete(ctx, key)
	return err
}

// Capabilities determines the capabilities of the backend.
func (s *EtcdStorage) Capabilities() storage.Capability {
	return storage.CapabilityDistributedLocking | storage.CapabilityWatching
}

// LockKey creates a distributed lock for the given key in the backend.
func (s *EtcdStorage) LockKey(ctx context.Context, key string) (storage.Mutex, error) {
	return &Mutex{
		s:   s,
		ctx: ctx,
		key: key,
	}, nil
}

// Mutex object.
type Mutex struct {
	s        *EtcdStorage
	ctx      context.Context
	key      string
	locked   bool
	eSession *concurrency.Session
	eMutex   *concurrency.Mutex
}

// Lock the key.
func (m *Mutex) Lock() error {
	if err := m.newSession(); err != nil {
		return err
	}

	if m.locked {
		return storage.ErrLocked
	}

	select {
	case _, ok := <-m.eSession.Done():
		if !ok {
			if err := m.newSession(); err != nil {
				return err
			}
		}
	default:
	}

	if err := m.eMutex.Lock(m.ctx); err != nil {
		if err == context.Canceled {
			return nil
		}
		return err
	}

	if _, err := m.s.c.Put(m.ctx, m.eMutex.Key(), "locked", etcdclient.WithLease(m.eSession.Lease())); err != nil {
		return err
	}

	m.locked = true
	return nil
}

// Unlock the key.
func (m *Mutex) Unlock() error {
	return m.eMutex.Unlock(m.ctx)
}

// Get value of the key.
func (m *Mutex) Get() (*apiv1.BackendItem, error) {
	return m.s.Get(m.ctx, m.key)
}

func (m *Mutex) newSession() error {
	if m.eSession != nil && m.eMutex != nil {
		return nil
	}

	session, err := concurrency.NewSession(m.s.c, concurrency.WithContext(m.ctx))
	if err != nil {
		return err
	}

	m.eSession = session
	m.eMutex = concurrency.NewMutex(session, m.key)

	return nil
}
