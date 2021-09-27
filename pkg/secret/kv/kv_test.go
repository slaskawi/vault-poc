package kv

import (
	"context"
	"testing"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	"google.golang.org/protobuf/types/known/anypb"

	apiv1 "github.com/slaskawi/vault-poc/api/v1"
	"github.com/slaskawi/vault-poc/pkg/barrier"
	"github.com/slaskawi/vault-poc/pkg/barrier/encryption"
	"github.com/slaskawi/vault-poc/pkg/storage"
	"github.com/slaskawi/vault-poc/pkg/storage/memory"
)

func TestKV(t *testing.T) {
	defer GinkgoRecover()

	RegisterFailHandler(Fail)
	RunSpecs(t, "kv")
}

var _ = Describe("kv", func() {
	back, err := memory.NewMemoryStorage(nil)
	Expect(err).NotTo(HaveOccurred())

	barr, err := barrier.NewBarrier(back)
	Expect(err).NotTo(HaveOccurred())

	gatekeeperKey, err := encryption.GenerateKey(apiv1.CipherType_AES256_GCM)
	Expect(err).NotTo(HaveOccurred())
	Expect(gatekeeperKey).NotTo(BeNil())

	ctx := context.Background()
	err = barr.Initialize(ctx, gatekeeperKey, nil)
	Expect(err).NotTo(HaveOccurred())

	err = barr.Unseal(ctx, gatekeeperKey)
	Expect(err).NotTo(HaveOccurred())

	kv := NewKV(barr)

	It("requires a namespace", func() {
		paths, err := kv.List(ctx, "/", "not-gonna-work")
		Expect(err).To(MatchError(ErrNoNamespace))
		Expect(paths).To(BeNil())
	})

	It("requires a path", func() {
		_, err := kv.Get(ctx, "namespace", "")
		Expect(err).To(MatchError(ErrInvalidPath))

		err = kv.Put(ctx, "namespace", nil)
		Expect(err).To(HaveOccurred())

		err = kv.Put(ctx, "namespace", &apiv1.Item{Key: ""})
		Expect(err).To(MatchError(ErrInvalidPath))

		err = kv.Delete(ctx, "namespace", "")
		Expect(err).To(MatchError(ErrInvalidPath))
	})

	It("requires printable characters in a namespace", func() {
		paths, err := kv.List(ctx, "\x01", "item1")
		Expect(err).To(MatchError(ErrInvalidPath))
		Expect(paths).To(BeNil())
	})

	It("requires printable characters in a path", func() {
		paths, err := kv.List(ctx, "namespace", "\x01")
		Expect(err).To(MatchError(ErrInvalidPath))
		Expect(paths).To(BeNil())
	})

	It("can put a new item in the store", func() {
		item := &apiv1.Item{
			Key: "folder1/item1",
			Map: map[string]*anypb.Any{
				"key1": {},
			},
		}

		err := kv.Put(ctx, "namespace", item)
		Expect(err).NotTo(HaveOccurred())
	})

	It("can list items from a store", func() {
		paths, err := kv.List(ctx, "namespace", "")
		Expect(err).NotTo(HaveOccurred())
		Expect(paths).To(HaveLen(1))
		Expect(paths[0]).To(Equal("folder1/"))
	})

	It("can list items from a folder", func() {
		paths, err := kv.List(ctx, "namespace", "folder1")
		Expect(err).NotTo(HaveOccurred())
		Expect(paths).To(HaveLen(1))
		Expect(paths[0]).To(Equal("item1"))
	})

	It("won't list items from another namespace", func() {
		paths, err := kv.List(ctx, "something-else", "")
		Expect(err).NotTo(HaveOccurred())
		Expect(paths).To(BeEmpty())
	})

	It("returns an error if key not found", func() {
		item, err := kv.Get(ctx, "namespace", "not-here")
		Expect(err).To(MatchError(storage.ErrNotFound))
		Expect(item).To(BeNil())
	})

	It("can get an item from the store", func() {
		item, err := kv.Get(ctx, "namespace", "folder1/item1")
		Expect(err).NotTo(HaveOccurred())
		Expect(item).NotTo(BeNil())
		Expect(item.Key).To(Equal("folder1/item1"))
		Expect(item.Map).NotTo(BeNil())
		Expect(item.Map["key1"]).NotTo(BeNil())
	})

	It("won't get an item with bad characters in the path", func() {
		item, err := kv.Get(ctx, "namespace", "folder1/item1\x00")
		Expect(err).To(MatchError(ErrInvalidPath))
		Expect(item).To(BeNil())
	})

	It("deletes an item from the store", func() {
		err := kv.Delete(ctx, "namespace", "folder1/item1")
		Expect(err).NotTo(HaveOccurred())
	})

	It("actually deleted the item", func() {
		item, err := kv.Get(ctx, "namespace", "folder1/item1")
		Expect(err).To(MatchError(storage.ErrNotFound))
		Expect(item).To(BeNil())
	})
})
