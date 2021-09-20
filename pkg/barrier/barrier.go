// Package barrier wraps a `backend.Storage` to add an encryption/decryption layer for all secrets stored in the backend.
package barrier

import (
	"context"
	"fmt"
	"sync"

	apiv1 "github.com/slaskawi/vault-poc/api/v1"
	"github.com/slaskawi/vault-poc/pkg/barrier/encryption"
	"github.com/slaskawi/vault-poc/pkg/barrier/keychain"
	"github.com/slaskawi/vault-poc/pkg/storage/backend"
	"google.golang.org/protobuf/proto"
)

const (
	barrierPath = "kstash/barrier/"
	keychainKey = "keychain"
	idKey       = "id"
	idLength    = 18
)

var (
	ErrBarrierAlreadyInitialized = fmt.Errorf("barrier is already initialized")
	ErrBarrierNotInitialized     = fmt.Errorf("barrier is not initialized")
	ErrBarrierSealed             = fmt.Errorf("barrier is sealed")
	ErrBarrierUnsealed           = fmt.Errorf("barrier is already unsealed")
	ErrBarrierInvalidKey         = fmt.Errorf("unseal failed due to invalid key")
	ErrDisallowedPath            = fmt.Errorf("key path is not allowed")
	ErrMixRawMapValues           = fmt.Errorf("cannot mix raw and map values")
)

var disallowedPaths = map[string]struct{}{
	barrierPath + keychainKey: {},
	barrierPath + idKey:       {},
}

// Barrier object.
type Barrier struct {
	backend  backend.Storage
	keychain *keychain.Keychain
	mu       sync.RWMutex
}

// NewBarrier returns a new Barrier object.
func NewBarrier(backend backend.Storage) (*Barrier, error) {
	b := &Barrier{
		backend: backend,
	}

	return b, nil
}

// IsInitialized determines if the secret store has been initialized.
func (b *Barrier) IsInitialized(ctx context.Context) (bool, error) {
	b.mu.RLock()
	defer b.mu.RUnlock()

	if b.keychain != nil {
		return true, nil
	}

	keys, err := b.backend.List(ctx, barrierPath)
	if err != nil {
		return false, fmt.Errorf("unable to detect initializtion: %w", err)
	}

	for _, key := range keys {
		if key == keychainKey {
			return true, nil
		}
	}

	return false, nil
}

// Initialize will create a new Keychain only if one doesn't already exist.
func (b *Barrier) Initialize(ctx context.Context, gatekeeperKey []byte) error {
	initialized, err := b.IsInitialized(ctx)
	if err != nil {
		return err
	}
	if initialized {
		return ErrBarrierAlreadyInitialized
	}

	b.mu.Lock()
	defer b.mu.Unlock()

	// create new id
	idB, err := encryption.GenerateKey(apiv1.CipherType_AES256_GCM)
	if err != nil {
		return fmt.Errorf("unable to generate new kstash ID: %w", err)
	}

	if err := b.backend.Put(ctx, &apiv1.BackendItem{
		Key: barrierPath + idKey,
		Val: idB,
	}); err != nil {
		return fmt.Errorf("unable to write generated kstash ID: %w", err)
	}

	// create new keychain
	b.keychain = keychain.NewKeychain()
	if err := b.keychain.Rotate(); err != nil {
		return fmt.Errorf("failed to create keychain: %w", err)
	}

	err = b.persistKeychain(ctx, gatekeeperKey)
	b.keychain = nil
	return err
}

// ID gets the barrier's ID that was created during Initialization.
// Returns `backend.ErrNotFound` if barrier has not been initialized.
func (b *Barrier) ID(ctx context.Context) (encryption.Hash, error) {
	bitem, err := b.backend.Get(ctx, barrierPath+idKey)
	if err != nil {
		return encryption.Hash{}, err
	}

	return encryption.FromHash(bitem.Val), nil
}

// Backend returns the underlying `backend.Storage` used to create the Barrier.
// Operations performed on the backend directly are not managed by the barrier.
func (b *Barrier) Backend() backend.Storage {
	return b.backend
}

// IsSealed determines if the secret store is initialized, but sealed.
func (b *Barrier) IsSealed(ctx context.Context) (bool, error) {
	initialized, err := b.IsInitialized(ctx)
	if err != nil {
		return false, err
	}
	if !initialized {
		return false, ErrBarrierNotInitialized
	}

	b.mu.RLock()
	defer b.mu.RUnlock()

	return b.keychain == nil, nil
}

// Unseal uses the given gatekeeper key to decrypt the Keychain. If the key is invalid, the unseal operation will fail.
func (b *Barrier) Unseal(ctx context.Context, gatekeeperKey []byte) error {
	sealed, err := b.IsSealed(ctx)
	if err != nil {
		return err
	}
	if !sealed {
		return ErrBarrierUnsealed
	}

	kc, err := b.retrieveKeychain(ctx, gatekeeperKey)
	if err != nil {
		return err
	}

	b.mu.Lock()
	defer b.mu.Unlock()

	b.keychain = kc
	return nil
}

// Seal will drop the current Keychain from memory, requiring an Unseal prior to any other operations.
func (b *Barrier) Seal() {
	b.mu.Lock()
	defer b.mu.Unlock()

	b.keychain = nil
}

// ChangeGatekeeperKey re-encrypts the current Keychain with the given gatekeeper key.
func (b *Barrier) ChangeGatekeeperKey(ctx context.Context, gatekeeperKey []byte) error {
	sealed, err := b.IsSealed(ctx)
	if err != nil {
		return err
	}
	if sealed {
		return ErrBarrierSealed
	}

	b.mu.Lock()
	defer b.mu.Unlock()

	return b.persistKeychain(ctx, gatekeeperKey)
}

// RotateEncryptionKey rotates the encryption key used for new writes to the physical storage backend.
func (b *Barrier) RotateEncryptionKey(ctx context.Context, gatekeeperKey []byte) error {
	sealed, err := b.IsSealed(ctx)
	if err != nil {
		return err
	}
	if sealed {
		return ErrBarrierSealed
	}

	b.mu.Lock()
	defer b.mu.Unlock()

	if err := b.keychain.Rotate(); err != nil {
		return err
	}

	return b.persistKeychain(ctx, gatekeeperKey)
}

// EncryptItem encrypts the given Item using the barrier's active encryption key. This is useful for encrypting/decrypting information that doesn't need to be written to storage.
func (b *Barrier) EncryptItem(item *apiv1.Item) (*apiv1.BackendItem, error) {
	bs, err := proto.Marshal(item)
	if err != nil {
		return nil, fmt.Errorf("unable to marshal item: %s: %w", item.Key, err)
	}

	encKey := b.keychain.ActiveKey()
	encrypted, err := encryption.Encrypt(encKey.Type, encKey.Key, bs)
	if err != nil {
		return nil, fmt.Errorf("unable to encrypt item: %s: %w", item.Key, err)
	}

	bitem := &apiv1.BackendItem{
		Key:             item.Key,
		EncryptionKeyID: encKey.Id,
		Val:             encrypted,
	}

	return bitem, nil
}

// DecryptItem decrypts the given Item using a known barrier encryption key ID. This is useful for encrypting/decrypting information that doesn't need to be written to storage.
func (b *Barrier) DecyptItem(bitem *apiv1.BackendItem) (*apiv1.Item, error) {
	if bitem.EncryptionKeyID == 0 {
		return nil, fmt.Errorf("encryptionKeyID cannot be zero")
	}

	encKey := b.keychain.Key(bitem.EncryptionKeyID)
	if encKey == nil {
		return nil, fmt.Errorf("unable to unencrypt value: reported EncryptionKeyID %d does not exist", bitem.EncryptionKeyID)
	}

	decrypted, err := encryption.Decrypt(encKey.Type, encKey.Key, bitem.Val)
	if err != nil {
		return nil, fmt.Errorf("unable to decrypt key: %s: %w", bitem.Key, err)
	}

	item := &apiv1.Item{}
	if err := proto.Unmarshal(decrypted, item); err != nil {
		return nil, fmt.Errorf("unable to unmarshal key: %s: %w", bitem.Key, err)
	}

	return item, nil
}

// List items in the given prefix.
func (b *Barrier) List(ctx context.Context, prefix string) ([]string, error) {
	sealed, err := b.IsSealed(ctx)
	if err != nil {
		return nil, err
	}
	if sealed {
		return nil, ErrBarrierSealed
	}

	return b.backend.List(ctx, prefix)
}

// Get an item from the storage backend.
func (b *Barrier) Get(ctx context.Context, key string) (*apiv1.Item, error) {
	sealed, err := b.IsSealed(ctx)
	if err != nil {
		return nil, err
	}
	if sealed {
		return nil, ErrBarrierSealed
	}
	if _, ok := disallowedPaths[key]; ok {
		return nil, ErrDisallowedPath
	}

	bitem, err := b.backend.Get(ctx, key)
	if err != nil {
		return nil, err
	}

	return b.DecyptItem(bitem)
}

// Put an item in the storage backend after encrypting it.
func (b *Barrier) Put(ctx context.Context, item *apiv1.Item) error {
	sealed, err := b.IsSealed(ctx)
	if err != nil {
		return err
	}
	if sealed {
		return ErrBarrierSealed
	}
	if _, ok := disallowedPaths[item.Key]; ok {
		return ErrDisallowedPath
	}

	if item.Map != nil && item.Raw != nil {
		return ErrMixRawMapValues
	}

	bitem, err := b.EncryptItem(item)
	if err != nil {
		return err
	}

	return b.backend.Put(ctx, bitem)
}

// Delete an item from the storage backend.
func (b *Barrier) Delete(ctx context.Context, key string) error {
	sealed, err := b.IsSealed(ctx)
	if err != nil {
		return err
	}
	if sealed {
		return ErrBarrierSealed
	}
	if _, ok := disallowedPaths[key]; ok {
		return ErrDisallowedPath
	}

	return b.backend.Delete(ctx, key)
}

func (b *Barrier) persistKeychain(ctx context.Context, gatekeeperKey []byte) error {
	snapshot, err := b.keychain.Snapshot(gatekeeperKey)
	if err != nil {
		return fmt.Errorf("failed to create keychain snapshot: %w", err)
	}

	item := &apiv1.BackendItem{
		Key:             barrierPath + keychainKey,
		EncryptionKeyID: uint32(apiv1.CipherType_AES256_GCM),
		Val:             snapshot,
	}
	if err := b.backend.Put(ctx, item); err != nil {
		return fmt.Errorf("failed to put keychain in backend storage: %w", err)
	}

	return nil
}

func (b *Barrier) retrieveKeychain(ctx context.Context, gatekeeperKey []byte) (*keychain.Keychain, error) {
	item, err := b.backend.Get(ctx, barrierPath+keychainKey)
	if err != nil {
		return nil, fmt.Errorf("unable to get keychain from backend storage: %w", err)
	}

	kc, err := keychain.FromSnapshot(gatekeeperKey, item.Val)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrBarrierInvalidKey, err)
	}

	return kc, nil
}
