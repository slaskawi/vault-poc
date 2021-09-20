package barrier

import (
	"context"
	"testing"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	"google.golang.org/protobuf/types/known/anypb"

	apiv1 "github.com/slaskawi/vault-poc/api/v1"
	"github.com/slaskawi/vault-poc/pkg/barrier/encryption"
	"github.com/slaskawi/vault-poc/pkg/storage/backend"
	"github.com/slaskawi/vault-poc/pkg/storage/backend/memory"
)

func TestBarrier(t *testing.T) {
	defer GinkgoRecover()

	RegisterFailHandler(Fail)
	RunSpecs(t, "barrier")
}

var _ = Describe("barrier", func() {
	ctx := context.Background()
	back := memory.NewMemoryStorage()
	barrier, err := NewBarrier(back)
	Expect(err).NotTo(HaveOccurred())
	Expect(barrier).NotTo(BeNil())

	gatekeeperKey, err := encryption.GenerateKey(apiv1.CipherType_AES256_GCM)
	Expect(err).NotTo(HaveOccurred())
	Expect(gatekeeperKey).NotTo(BeNil())

	It("can report not initialized status", func() {
		initialized, err := barrier.IsInitialized(ctx)
		Expect(err).NotTo(HaveOccurred())
		Expect(initialized).To(BeFalse())

		sealed, err := barrier.IsSealed(ctx)
		Expect(err).To(MatchError(ErrBarrierNotInitialized))
		Expect(sealed).To(BeFalse())

		id, err := barrier.ID(ctx)
		Expect(err).To(MatchError(backend.ErrNotFound))
		Expect(id).To(BeNil())
	})

	It("can initialize", func() {
		err := barrier.Initialize(ctx, gatekeeperKey)
		Expect(err).NotTo(HaveOccurred())

		initialized, err := barrier.IsInitialized(ctx)
		Expect(err).NotTo(HaveOccurred())
		Expect(initialized).To(BeTrue())

		sealed, err := barrier.IsSealed(ctx)
		Expect(err).NotTo(HaveOccurred())
		Expect(sealed).To(BeTrue())

		id, err := barrier.ID(ctx)
		Expect(err).NotTo(HaveOccurred())
		Expect(id).NotTo(BeNil())
		Expect(id.String()).NotTo(BeEmpty())
	})

	It("can unseal", func() {
		err := barrier.Unseal(ctx, gatekeeperKey)
		Expect(err).NotTo(HaveOccurred())

		initialized, err := barrier.IsInitialized(ctx)
		Expect(err).NotTo(HaveOccurred())
		Expect(initialized).To(BeTrue())

		sealed, err := barrier.IsSealed(ctx)
		Expect(err).NotTo(HaveOccurred())
		Expect(sealed).To(BeFalse())
	})

	It("can seal", func() {
		barrier.Seal()

		initialized, err := barrier.IsInitialized(ctx)
		Expect(err).NotTo(HaveOccurred())
		Expect(initialized).To(BeTrue())

		sealed, err := barrier.IsSealed(ctx)
		Expect(err).NotTo(HaveOccurred())
		Expect(sealed).To(BeTrue())
	})

	It("fails to operate if barrier is sealed", func() {
		sealed, err := barrier.IsSealed(ctx)
		Expect(err).NotTo(HaveOccurred())
		Expect(sealed).To(BeTrue())

		_, err = barrier.List(ctx, "")
		Expect(err).To(HaveOccurred())
		Expect(err).To(MatchError(ErrBarrierSealed))

		_, err = barrier.Get(ctx, "test")
		Expect(err).To(HaveOccurred())
		Expect(err).To(MatchError(ErrBarrierSealed))

		err = barrier.Put(ctx, nil)
		Expect(err).To(HaveOccurred())
		Expect(err).To(MatchError(ErrBarrierSealed))

		err = barrier.Delete(ctx, "test")
		Expect(err).To(HaveOccurred())
		Expect(err).To(MatchError(ErrBarrierSealed))

		err = barrier.ChangeGatekeeperKey(ctx, nil)
		Expect(err).To(HaveOccurred())
		Expect(err).To(MatchError(ErrBarrierSealed))

		err = barrier.RotateEncryptionKey(ctx, nil)
		Expect(err).To(HaveOccurred())
		Expect(err).To(MatchError(ErrBarrierSealed))
	})

	It("can unseal a second time", func() {
		err := barrier.Unseal(ctx, gatekeeperKey)
		Expect(err).NotTo(HaveOccurred())

		initialized, err := barrier.IsInitialized(ctx)
		Expect(err).NotTo(HaveOccurred())
		Expect(initialized).To(BeTrue())

		sealed, err := barrier.IsSealed(ctx)
		Expect(err).NotTo(HaveOccurred())
		Expect(sealed).To(BeFalse())
	})

	It("fails with ErrNotFound on fake key once barrier is unsealed", func() {
		sealed, err := barrier.IsSealed(ctx)
		Expect(err).NotTo(HaveOccurred())
		Expect(sealed).To(BeFalse())

		item, err := barrier.Get(ctx, "test")
		Expect(err).To(HaveOccurred())
		Expect(err).To(MatchError(backend.ErrNotFound))
		Expect(item).To(BeNil())
	})

	It("prevents operations on disallowed keys", func() {
		item, err := barrier.Get(ctx, barrierPath+keychainKey)
		Expect(err).To(HaveOccurred())
		Expect(err).To(MatchError(ErrDisallowedPath))
		Expect(item).To(BeNil())

		err = barrier.Put(ctx, &apiv1.Item{Key: barrierPath + keychainKey})
		Expect(err).To(HaveOccurred())
		Expect(err).To(MatchError(ErrDisallowedPath))

		err = barrier.Delete(ctx, barrierPath+keychainKey)
		Expect(err).To(HaveOccurred())
		Expect(err).To(MatchError(ErrDisallowedPath))
	})

	It("cannot put raw and map data in same key", func() {
		item := &apiv1.Item{
			Key: "testing",
			Raw: []byte("raw data"),
			Map: map[string]*anypb.Any{
				"key": {},
			},
		}

		err := barrier.Put(ctx, item)
		Expect(err).To(HaveOccurred())
		Expect(err).To(MatchError(ErrMixRawMapValues))
	})

	It("puts a new encrypted raw value", func() {
		data := []byte("raw byte test")
		item := &apiv1.Item{
			Key: "testing/key1",
			Raw: data,
		}

		err := barrier.Put(ctx, item)
		Expect(err).NotTo(HaveOccurred())

		By("ensuring raw value was encrypted")
		bitem, err := barrier.backend.Get(ctx, "testing/key1")
		Expect(err).NotTo(HaveOccurred())
		Expect(bitem).NotTo(BeNil())
		Expect(bitem.Key).To(Equal("testing/key1"))
		Expect(bitem.EncryptionKeyID).To(Equal(uint32(1)))
		Expect(len(bitem.Val) > 15).To(BeTrue())

		By("ensuring we can decrypt raw value")
		item, err = barrier.Get(ctx, "testing/key1")
		Expect(err).NotTo(HaveOccurred())
		Expect(item).NotTo(BeNil())
		Expect(item.Key).To(Equal("testing/key1"))
		Expect(item.Map).To(BeNil())
		Expect(item.Raw).To(Equal(data))
	})

	It("puts a new encrypted map value", func() {
		m := map[string]*anypb.Any{
			"key": {Value: []byte("val")},
		}
		item := &apiv1.Item{
			Key: "testing/key2",
			Map: m,
		}

		err := barrier.Put(ctx, item)
		Expect(err).NotTo(HaveOccurred())

		By("ensuring map value was encrypted")
		bitem, err := barrier.backend.Get(ctx, "testing/key2")
		Expect(err).NotTo(HaveOccurred())
		Expect(bitem).NotTo(BeNil())
		Expect(bitem.Key).To(Equal("testing/key2"))
		Expect(bitem.EncryptionKeyID).To(Equal(uint32(1)))
		Expect(len(bitem.Val) > 7).To(BeTrue())

		By("ensuring we can decrypt map value")
		item, err = barrier.Get(ctx, "testing/key2")
		Expect(err).NotTo(HaveOccurred())
		Expect(item).NotTo(BeNil())
		Expect(item.Key).To(Equal("testing/key2"))
		Expect(item.Raw).To(BeNil())
		Expect(item.Map).NotTo(BeNil())
		Expect(item.Map).To(HaveLen(1))
		Expect(item.Map["key"].Value).To(Equal(m["key"].Value))
	})

	It("lists keys", func() {
		keys, err := barrier.List(ctx, "testing/")
		Expect(err).NotTo(HaveOccurred())
		Expect(keys).To(HaveLen(2))
		Expect(keys[0]).To(Equal("key1"))
		Expect(keys[1]).To(Equal("key2"))

	})

	It("deletes a key", func() {
		err := barrier.Delete(ctx, "testing/key2")
		Expect(err).NotTo(HaveOccurred())

		item, err := barrier.Get(ctx, "testing/key2")
		Expect(err).To(HaveOccurred())
		Expect(err).To(MatchError(backend.ErrNotFound))
		Expect(item).To(BeNil())
	})

	It("can change the gatekeeper key", func() {
		gatekeeperKey, err = encryption.GenerateKey(apiv1.CipherType_AES256_GCM)
		Expect(err).NotTo(HaveOccurred())
		Expect(gatekeeperKey).NotTo(BeEmpty())

		err = barrier.ChangeGatekeeperKey(ctx, gatekeeperKey)
		Expect(err).NotTo(HaveOccurred())

		barrier.Seal()
		sealed, err := barrier.IsSealed(ctx)
		Expect(err).NotTo(HaveOccurred())
		Expect(sealed).To(BeTrue())

		err = barrier.Unseal(ctx, gatekeeperKey)
		Expect(err).NotTo(HaveOccurred())

		item, err := barrier.Get(ctx, "testing/key1")
		Expect(err).NotTo(HaveOccurred())
		Expect(item).NotTo(BeNil())
		Expect(item.Key).To(Equal("testing/key1"))
		Expect(item.Map).To(BeNil())
		Expect(item.Raw).NotTo(BeEmpty())
	})

	It("can rotate encryption keys", func() {
		err := barrier.RotateEncryptionKey(ctx, gatekeeperKey)
		Expect(err).NotTo(HaveOccurred())

		activeKey := barrier.keychain.ActiveKey()
		Expect(activeKey).NotTo(BeNil())
		Expect(activeKey.Id).To(Equal(uint32(2)))

		By("ensuring we can decrypt secrets using older keys")
		bitem, err := barrier.backend.Get(ctx, "testing/key1")
		Expect(err).NotTo(HaveOccurred())
		Expect(bitem).NotTo(BeNil())
		Expect(bitem.Key).To(Equal("testing/key1"))
		Expect(bitem.EncryptionKeyID).To(Equal(uint32(1)))

		item, err := barrier.Get(ctx, "testing/key1")
		Expect(err).NotTo(HaveOccurred())
		Expect(item).NotTo(BeNil())
		Expect(item.Key).To(Equal("testing/key1"))
		Expect(item.Map).To(BeNil())
		Expect(item.Raw).NotTo(BeEmpty())

		By("ensuring new puts use the active key")
		item = &apiv1.Item{
			Key: "testing/key1",
			Raw: item.Raw,
		}

		err = barrier.Put(ctx, item)
		Expect(err).NotTo(HaveOccurred())

		bitem, err = barrier.backend.Get(ctx, "testing/key1")
		Expect(err).NotTo(HaveOccurred())
		Expect(bitem).NotTo(BeNil())
		Expect(bitem.Key).To(Equal("testing/key1"))
		Expect(bitem.EncryptionKeyID).To(Equal(uint32(activeKey.Id)))

		item, err = barrier.Get(ctx, "testing/key1")
		Expect(err).NotTo(HaveOccurred())
		Expect(item).NotTo(BeNil())
		Expect(item.Key).To(Equal("testing/key1"))
		Expect(item.Map).To(BeNil())
		Expect(item.Raw).NotTo(BeEmpty())
	})
})
