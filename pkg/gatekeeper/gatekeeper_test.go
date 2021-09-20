package gatekeeper

import (
	"context"
	"testing"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	apiv1 "github.com/slaskawi/vault-poc/api/v1"
	"github.com/slaskawi/vault-poc/pkg/barrier"
	"github.com/slaskawi/vault-poc/pkg/barrier/encryption"
	"github.com/slaskawi/vault-poc/pkg/storage/backend"
	"github.com/slaskawi/vault-poc/pkg/storage/backend/memory"
)

func TestGatekeeper(t *testing.T) {
	defer GinkgoRecover()

	RegisterFailHandler(Fail)
	RunSpecs(t, "gatekeeper")
}

var _ = Describe("gatekeeper", func() {
	ctx := context.Background()
	back := memory.NewMemoryStorage()
	barr, err := barrier.NewBarrier(back)
	Expect(err).NotTo(HaveOccurred())
	Expect(barr).NotTo(BeNil())

	gk, err := NewGatekeeper(barr)
	Expect(err).NotTo(HaveOccurred())
	Expect(gk).NotTo(BeNil())

	gatekeeperKey, err := encryption.GenerateKey(apiv1.CipherType_AES256_GCM)
	Expect(err).NotTo(HaveOccurred())
	Expect(gatekeeperKey).NotTo(BeNil())

	var token string

	It("should fail if barrier hasn't been initialized", func() {
		_, err := gk.GenerateGatekeeperToken(ctx, nil)
		Expect(err).To(HaveOccurred())
		Expect(err).To(MatchError(barrier.ErrBarrierNotInitialized))
	})

	It("should generate gatekeeper tokens from an initialized barrier", func() {
		err := barr.Initialize(ctx, gatekeeperKey)
		Expect(err).NotTo(HaveOccurred())

		token, err = gk.GenerateGatekeeperToken(ctx, gatekeeperKey)
		Expect(err).NotTo(HaveOccurred())
		Expect(token).NotTo(BeEmpty())
	})

	It("should unseal the barrier using a gatekeeper token", func() {
		err := gk.UnsealWithGatekeeperToken(ctx, token)
		Expect(err).NotTo(HaveOccurred())

		sealed, err := barr.IsSealed(ctx)
		Expect(err).NotTo(HaveOccurred())
		Expect(sealed).To(BeFalse())
	})

	It("should fail if already unsealed", func() {
		err := gk.UnsealWithGatekeeperToken(ctx, token)
		Expect(err).To(HaveOccurred())
		Expect(err).To(MatchError(barrier.ErrBarrierUnsealed))
	})

	It("should have revoked token after successful unseal", func() {
		barr.Seal()

		err := gk.UnsealWithGatekeeperToken(ctx, token)
		Expect(err).To(HaveOccurred())
		Expect(err).To(MatchError(backend.ErrNotFound))
	})

	It("should generate sharded unseal keys and use those keys to unseal the barrier", func() {
		keys, err := gk.GenerateShardedKeys(gatekeeperKey, 5, 3)
		Expect(err).NotTo(HaveOccurred())
		Expect(keys).To(HaveLen(5))

		err = gk.CombineShardedKeys(ctx, keys[:2])
		Expect(err).To(HaveOccurred())

		err = gk.CombineShardedKeys(ctx, keys[:3])
		Expect(err).NotTo(HaveOccurred())

		sealed, err := barr.IsSealed(ctx)
		Expect(err).NotTo(HaveOccurred())
		Expect(sealed).To(BeFalse())
	})
})
