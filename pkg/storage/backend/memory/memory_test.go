package memory

import (
	"context"
	"testing"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"

	apiv1 "github.com/slaskawi/vault-poc/api/v1"
	"github.com/slaskawi/vault-poc/pkg/storage/backend"
)

func TestMemory(t *testing.T) {
	defer GinkgoRecover()

	RegisterFailHandler(Fail)
	RunSpecs(t, "memory")
}

var _ = Describe("memory", func() {
	var mem backend.Storage
	ctx := context.Background()

	It("can create new memory storage and load with items", func() {
		mem = NewMemoryStorage()
		err := mem.Put(ctx, &apiv1.BackendItem{
			Key: "test/key1",
			Val: []byte("key1"),
		})
		Expect(err).NotTo(HaveOccurred())

		err = mem.Put(ctx, &apiv1.BackendItem{
			Key: "test/key2",
			Val: []byte("key2"),
		})
		Expect(err).NotTo(HaveOccurred())

		err = mem.Put(ctx, &apiv1.BackendItem{
			Key: "test/key2/subkey1",
			Val: []byte("key2,subkey2"),
		})
		Expect(err).NotTo(HaveOccurred())
	})

	It("can list items", func() {
		keys, err := mem.List(ctx, "")
		Expect(err).NotTo(HaveOccurred())
		Expect(len(keys)).To(Equal(1))
		Expect(keys[0]).To(Equal("test/"))

		keys, err = mem.List(ctx, "test/")
		Expect(err).NotTo(HaveOccurred())
		Expect(len(keys)).To(Equal(3))
		Expect(keys[0]).To(Equal("key1"))
		Expect(keys[1]).To(Equal("key2"))
		Expect(keys[2]).To(Equal("key2/"))

		keys, err = mem.List(ctx, "test/key2/")
		Expect(err).NotTo(HaveOccurred())
		Expect(len(keys)).To(Equal(1))
		Expect(keys[0]).To(Equal("subkey1"))
	})
})
