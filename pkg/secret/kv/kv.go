package kv

import (
	"context"
	"fmt"
	"strings"
	"unicode"

	apiv1 "github.com/slaskawi/vault-poc/api/v1"
	"github.com/slaskawi/vault-poc/pkg/barrier"
)

const namespacesPath = "namespaces/"

var (
	ErrInvalidPath = fmt.Errorf("invalid characters in path")
	ErrNoNamespace = fmt.Errorf("no namespace specified")
)

// KV object.
type KV struct {
	b *barrier.Barrier
}

// NewKV creates a new KV object.
func NewKV(b *barrier.Barrier) *KV {
	return &KV{b: b}
}

// List keys in a namespace.
func (k *KV) List(ctx context.Context, namespace, path string) ([]string, error) {
	path, err := getKVPath(namespace, path)
	if err != nil {
		return nil, err
	}

	return k.b.List(ctx, path)
}

// Get a key from a namespace.
func (k *KV) Get(ctx context.Context, namespace, path string) (*apiv1.Item, error) {
	if len(strings.TrimSuffix(path, "/")) == 0 {
		return nil, ErrInvalidPath
	}

	path, err := getKVPath(namespace, path)
	if err != nil {
		return nil, err
	}

	item, err := k.b.Get(ctx, path)
	if err != nil {
		return nil, err
	}

	item.Key = trimKVPath(namespace, path)
	return item, nil
}

// Put a key into a namespace.
func (k *KV) Put(ctx context.Context, namespace string, item *apiv1.Item) error {
	if item == nil {
		return fmt.Errorf("item cannot be nil")
	}

	if len(strings.TrimSuffix(item.Key, "/")) == 0 {
		return ErrInvalidPath
	}

	path, err := getKVPath(namespace, item.Key)
	if err != nil {
		return err
	}

	item.Key = path
	return k.b.Put(ctx, item)
}

// Delete a key from a namespace.
func (k *KV) Delete(ctx context.Context, namespace, path string) error {
	if len(strings.TrimSuffix(path, "/")) == 0 {
		return ErrInvalidPath
	}

	path, err := getKVPath(namespace, path)
	if err != nil {
		return err
	}

	return k.b.Delete(ctx, path)
}

func getKVPath(namespace, path string) (string, error) {
	namespace = strings.Trim(namespace, "/")
	if len(namespace) == 0 {
		return "", ErrNoNamespace
	}

	if strings.IndexFunc(namespace, func(r rune) bool {
		return !unicode.IsPrint(r)
	}) > -1 {
		return "", ErrInvalidPath
	}

	if strings.IndexFunc(path, func(r rune) bool {
		return !unicode.IsPrint(r)
	}) > -1 {
		return "", ErrInvalidPath
	}

	return namespacesPath + namespace + "/kv/" + strings.TrimPrefix(path, "/"), nil
}

func trimKVPath(namespace, path string) string {
	return strings.TrimPrefix(path, namespacesPath+namespace+"/kv/")
}
