package etcd

import (
	"context"
	"fmt"
	"sort"
	"strings"

	etcdclient "go.etcd.io/etcd/client/v3"
	"google.golang.org/protobuf/proto"

	apiv1 "github.com/slaskawi/vault-poc/api/v1"
	"github.com/slaskawi/vault-poc/pkg/storage/backend"
)

// EtcdStorage object.
type EtcdStorage struct {
	config *EtcdConfig
	c      *etcdclient.Client
}

// NewEtcdStorage returns a new EtcdStorage object.
func NewEtcdStorage(config *EtcdConfig) (backend.Storage, error) {
	if config == nil {
		config = &EtcdConfig{
			Endpoints: []string{"http://127.0.0.1:2379"},
		}
	}

	etcdConfig := &etcdclient.Config{
		Endpoints: config.Endpoints,
		Username:  config.Username,
		Password:  config.Password,
	}

	c, err := etcdclient.New(*etcdConfig)
	if err != nil {
		return nil, err
	}

	return &EtcdStorage{
		config: config,
		c:      c,
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
		return nil, backend.ErrNotFound
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
