package keychain

import (
	"testing"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"

	apiv1 "github.com/slaskawi/vault-poc/api/v1"
	"github.com/slaskawi/vault-poc/pkg/barrier/encryption"
)

func TestKeychain(t *testing.T) {
	defer GinkgoRecover()

	RegisterFailHandler(Fail)
	RunSpecs(t, "keychain")
}

var _ = Describe("keychain", func() {
	var kc *Keychain
	var gatekeeperKey []byte
	var snapshot []byte

	It("create a new Keychain", func() {
		kc = NewKeychain()
		Expect(kc).NotTo(BeNil())
		Expect(kc.keys).NotTo(BeNil())
		Expect(kc.keys).To(BeEmpty())
	})

	It("can rotate keys", func() {
		err := kc.Rotate()
		Expect(err).NotTo(HaveOccurred())
		Expect(kc.keys).NotTo(BeEmpty())
		Expect(kc.ActiveKey()).NotTo(BeNil())
		Expect(kc.ActiveKey().Id).To(Equal(uint32(1)))
		Expect(kc.ActiveKey().Key).NotTo(BeEmpty())

		err = kc.Rotate()
		Expect(err).NotTo(HaveOccurred())
		Expect(len(kc.keys)).To(Equal(2))
	})

	It("fails to add an existing key", func() {
		key := &apiv1.EncryptionKey{
			Id:   1,
			Type: apiv1.CipherType_AES256_GCM,
			Key:  []byte("fake"),
		}
		err := kc.Add(key)
		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(ContainSubstring("already exists"))
	})

	It("can take an encrypted snapshot", func() {
		var err error
		gatekeeperKey, err = encryption.GenerateKey(apiv1.CipherType_AES256_GCM)
		Expect(err).NotTo(HaveOccurred())
		Expect(gatekeeperKey).NotTo(BeEmpty())

		snapshot, err = kc.Snapshot(gatekeeperKey)
		Expect(err).NotTo(HaveOccurred())
		Expect(snapshot).NotTo(BeEmpty())
	})

	It("can restore an encrypted snapshot", func() {
		newKC, err := FromSnapshot(gatekeeperKey, snapshot)
		Expect(err).NotTo(HaveOccurred())
		Expect(newKC).NotTo(BeNil())
		Expect(len(newKC.keys)).To(Equal(len(kc.keys)))

		for i, newKey := range newKC.keys {
			key := kc.keys[i]
			Expect(newKey.Id).To(Equal(key.Id))
			Expect(newKey.Created.Seconds).To(Equal(key.Created.Seconds))
			Expect(newKey.Key).To(Equal(key.Key))
			Expect(newKey.Type).To(Equal(key.Type))
		}
	})

	It("fails to restore an encrypted snapshot with the wrong key", func() {
		badKey, err := encryption.GenerateKey(apiv1.CipherType_AES256_GCM)
		Expect(err).NotTo(HaveOccurred())
		Expect(badKey).NotTo(BeEmpty())

		newKC, err := FromSnapshot(badKey, snapshot)
		Expect(err).To(HaveOccurred())
		Expect(newKC).To(BeNil())
	})

	It("can get key by ID", func() {
		key := kc.Key(1)
		Expect(key).NotTo(BeNil())
		Expect(key.Key).NotTo(BeEmpty())
	})

	It("can remove a key by ID", func() {
		kc.Remove(2)
		Expect(len(kc.keys)).To(Equal(1))
		Expect(kc.ActiveKey().Id).To(Equal(uint32(1)))
	})
})
