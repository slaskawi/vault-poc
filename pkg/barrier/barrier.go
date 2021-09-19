package barrier

import (
	"context"
	"fmt"
	"sync"

	apiv1 "github.com/slaskawi/vault-poc/api/v1"
	"github.com/slaskawi/vault-poc/pkg/barrier/keychain"
	"github.com/slaskawi/vault-poc/pkg/storage/backend"
)

const (
	keychainPath = "oss/barrier/keychain"
)

var (
	ErrBarrierAlreadyInitialized = fmt.Errorf("barrier is already initialized")
	ErrBarrierNotInitialized     = fmt.Errorf("barrier is not initialized")
	ErrBarrierSealed             = fmt.Errorf("barrier is sealed")
	ErrBarrierUnsealed           = fmt.Errorf("barrier is already unsealed")
	ErrBarrierInvalidKey         = fmt.Errorf("unseal failed due to invalid key")
)

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

	keys, err := b.backend.List(ctx, keychainPath)
	if err != nil {
		return false, fmt.Errorf("unable to detect initializtion: %w", err)
	}

	found := false
	for _, key := range keys {
		if key == keychainPath {
			found = true
			break
		}
	}

	return found, nil
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

	b.keychain = keychain.NewKeychain()
	if err := b.keychain.Rotate(); err != nil {
		return fmt.Errorf("failed to create keychain: %w", err)
	}

	return b.persistKeychain(ctx, gatekeeperKey)
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

func (b *Barrier) persistKeychain(ctx context.Context, gatekeeperKey []byte) error {
	snapshot, err := b.keychain.Snapshot(gatekeeperKey)
	if err != nil {
		return fmt.Errorf("failed to create keychain snapshot: %w", err)
	}

	item := &apiv1.BackendItem{
		Key:             keychainPath,
		EncryptionKeyID: uint32(apiv1.CipherType_AES256_GCM),
		Val:             snapshot,
	}
	if err := b.backend.Put(ctx, item); err != nil {
		return fmt.Errorf("failed to put keychain in backend storage: %w", err)
	}

	return nil
}

func (b *Barrier) retrieveKeychain(ctx context.Context, gatekeeperKey []byte) (*keychain.Keychain, error) {
	item, err := b.backend.Get(ctx, keychainPath)
	if err != nil {
		return nil, fmt.Errorf("unable to get keychain from backend storage: %w", err)
	}

	kc, err := keychain.FromSnapshot(gatekeeperKey, item.Val)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrBarrierInvalidKey, err)
	}

	return kc, nil
}
