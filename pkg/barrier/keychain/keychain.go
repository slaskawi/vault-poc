// Package keychain manages known encryption keys for the barrier.
package keychain

import (
	"fmt"
	"sync"

	apiv1 "github.com/slaskawi/vault-poc/api/v1"
	"github.com/slaskawi/vault-poc/pkg/barrier/encryption"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"
)

const keychainName = "keychain"

// Keychain object.
type Keychain struct {
	keys []*apiv1.EncryptionKey

	mu sync.RWMutex
}

// NewKeychain returns a new Keychain object.
func NewKeychain() *Keychain {
	return &Keychain{
		keys: []*apiv1.EncryptionKey{},
	}
}

// FromSnapshot returns a new Keychain object from an encrypted KeychainSnapshot.
func FromSnapshot(gatekeeperKey []byte, snapshot []byte) (*Keychain, error) {
	data, err := encryption.Decrypt(apiv1.CipherType_AES256_GCM, gatekeeperKey, snapshot)
	if err != nil {
		return nil, err
	}

	snap := &apiv1.KeychainSnapshot{}
	if err := proto.Unmarshal(data, snap); err != nil {
		return nil, err
	}

	if snap.Name != keychainName {
		return nil, fmt.Errorf("unknown snapshot format")
	}

	return &Keychain{
		keys: snap.Keys,
	}, nil
}

// Snapshot returns a new encrypted KeychainSnapshot.
func (k *Keychain) Snapshot(gatekeeperKey []byte) ([]byte, error) {
	k.mu.Lock()
	defer k.mu.Unlock()

	snap := &apiv1.KeychainSnapshot{
		Name:    keychainName,
		Keys:    k.keys,
		Created: timestamppb.Now(),
	}

	data, err := proto.Marshal(snap)
	if err != nil {
		return nil, err
	}

	return encryption.Encrypt(apiv1.CipherType_AES256_GCM, gatekeeperKey, data)
}

// Key gets the specified Key by ID.
func (k *Keychain) Key(id uint32) *apiv1.EncryptionKey {
	k.mu.RLock()
	defer k.mu.RUnlock()

	for _, key := range k.keys {
		if key.Id == id {
			return key
		}
	}

	return nil
}

// ActiveKey gets the active Key.
func (k *Keychain) ActiveKey() *apiv1.EncryptionKey {
	k.mu.RLock()
	defer k.mu.RUnlock()

	if len(k.keys) == 0 {
		return nil
	}

	return k.keys[(len(k.keys) - 1)]
}

// Add a new Key to the Keychain.
func (k *Keychain) Add(key *apiv1.EncryptionKey) error {
	k.mu.Lock()
	defer k.mu.Unlock()

	if key.Id == 0 {
		if len(k.keys) == 0 {
			key.Id = 1
		} else {
			key.Id = k.keys[len(k.keys)-1].Id + 1
		}
	}

	if key.Created == nil {
		key.Created = timestamppb.Now()
	}

	for _, exKey := range k.keys {
		if exKey.Id == key.Id {
			return fmt.Errorf("a key with ID %d already exists on the Keychain", key.Id)
		}
	}

	k.keys = append(k.keys, key)
	return nil
}

// Remove a Key from the Keychain.
func (k *Keychain) Remove(id uint32) {
	k.mu.Lock()
	defer k.mu.Unlock()

	if len(k.keys) == 0 {
		return
	}

	keys := k.keys[:0]
	for _, key := range k.keys {
		if key.Id != id {
			keys = append(keys, key)
		}
	}
	k.keys = keys
}

// Rotate generates a new key and activates it.
func (k *Keychain) Rotate() error {
	keyBS, err := encryption.GenerateKey(apiv1.CipherType_AES256_GCM)
	if err != nil {
		return err
	}

	key := &apiv1.EncryptionKey{
		Type: apiv1.CipherType_AES256_GCM,
		Key:  keyBS,
	}

	return k.Add(key)
}
