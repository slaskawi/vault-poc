package gatekeeper

import (
	"context"
	"testing"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	apiv1 "github.com/slaskawi/vault-poc/api/v1"
	"github.com/slaskawi/vault-poc/pkg/barrier"
	"github.com/slaskawi/vault-poc/pkg/barrier/encryption"
	"github.com/slaskawi/vault-poc/pkg/storage/memory"
)

func TestGatekeeper(t *testing.T) {
	defer GinkgoRecover()

	RegisterFailHandler(Fail)
	RunSpecs(t, "gatekeeper")
}

func buildGatekeeper() (*barrier.Barrier, *Gatekeeper, error) {
	back, err := memory.NewMemoryStorage(nil)
	if err != nil {
		return nil, nil, err
	}

	barr, err := barrier.NewBarrier(back)
	if err != nil {
		return nil, nil, err
	}

	gk, err := NewGatekeeper(back, barr)
	if err != nil {
		return nil, nil, err
	}

	return barr, gk, nil
}

var _ = Describe("gatekeeper", func() {
	ctx := context.Background()

	barr, gk, err := buildGatekeeper()
	Expect(err).NotTo(HaveOccurred())
	Expect(barr).NotTo(BeNil())
	Expect(gk).NotTo(BeNil())

	gatekeeperKey, err := encryption.GenerateKey(apiv1.CipherType_AES256_GCM)
	Expect(err).NotTo(HaveOccurred())
	Expect(gatekeeperKey).NotTo(BeNil())

	var token string
	var keys []string

	It("should fail if barrier hasn't been initialized", func() {
		_, err := gk.GenerateGatekeeperToken(ctx, nil)
		Expect(err).To(HaveOccurred())
		Expect(err).To(MatchError(barrier.ErrBarrierNotInitialized))
	})

	It("should generate gatekeeper tokens from an initialized barrier", func() {
		err := barr.Initialize(ctx, gatekeeperKey, nil)
		Expect(err).NotTo(HaveOccurred())

		token, err = gk.GenerateGatekeeperToken(ctx, gatekeeperKey)
		Expect(err).NotTo(HaveOccurred())
		Expect(token).NotTo(BeEmpty())
	})

	It("should unseal the barrier using a gatekeeper token", func() {
		err := gk.UnsealWithGatekeeperToken(ctx, token, false)
		Expect(err).NotTo(HaveOccurred())

		sealed, err := barr.IsSealed(ctx)
		Expect(err).NotTo(HaveOccurred())
		Expect(sealed).To(BeFalse())
	})

	It("should fail if already unsealed", func() {
		err := gk.UnsealWithGatekeeperToken(ctx, token, false)
		Expect(err).To(HaveOccurred())
		Expect(err).To(MatchError(barrier.ErrBarrierUnsealed))
	})

	It("should have revoked token after successful unseal", func() {
		barr.Seal()

		err := gk.UnsealWithGatekeeperToken(ctx, token, false)
		Expect(err).To(HaveOccurred())
		Expect(err).To(MatchError(ErrInvalidGatekeeperToken))
	})

	It("should generate sharded unseal keys and use those keys to unseal the barrier", func() {
		keys, err := gk.GenerateUnsealKeys(gatekeeperKey, 5, 3)
		Expect(err).NotTo(HaveOccurred())
		Expect(keys).To(HaveLen(5))

		err = gk.UnsealWithUnsealKeys(ctx, keys[:2])
		Expect(err).To(HaveOccurred())

		err = gk.UnsealWithUnsealKeys(ctx, keys[:3])
		Expect(err).NotTo(HaveOccurred())

		sealed, err := barr.IsSealed(ctx)
		Expect(err).NotTo(HaveOccurred())
		Expect(sealed).To(BeFalse())
	})

	It("should renew gatekeeperTokens if requested", func() {
		token, err = gk.GenerateGatekeeperToken(ctx, gatekeeperKey)
		Expect(err).NotTo(HaveOccurred())
		Expect(token).NotTo(BeEmpty())

		barr.Seal()
		err := gk.UnsealWithGatekeeperToken(ctx, token, true)
		Expect(err).NotTo(HaveOccurred())

		sealed, err := barr.IsSealed(ctx)
		Expect(err).NotTo(HaveOccurred())
		Expect(sealed).To(BeFalse())
	})

	It("should use renewed token to rotate itself", func() {
		token, err = gk.RotateGatekeeperToken(ctx, token)
		Expect(err).NotTo(HaveOccurred())
		Expect(token).NotTo(BeEmpty())

		barr.Seal()
		err := gk.UnsealWithGatekeeperToken(ctx, token, true)
		Expect(err).NotTo(HaveOccurred())

		sealed, err := barr.IsSealed(ctx)
		Expect(err).NotTo(HaveOccurred())
		Expect(sealed).To(BeFalse())
	})

	It("should use rotated token to rotate the active encryption key", func() {
		err = gk.RotateEncryptionKeyWithGatekeeperToken(ctx, token, false)
		Expect(err).NotTo(HaveOccurred())
	})

	It("should have revoked token after successful encryption rotation since we did not request renewal", func() {
		barr.Seal()

		err := gk.UnsealWithGatekeeperToken(ctx, token, false)
		Expect(err).To(HaveOccurred())
		Expect(err).To(MatchError(ErrInvalidGatekeeperToken))
	})

	It("should wipe the store and report unintialized", func() {
		barr, gk, err = buildGatekeeper()
		Expect(err).NotTo(HaveOccurred())
		Expect(barr).NotTo(BeNil())
		Expect(gk).NotTo(BeNil())

		initialized, err := barr.IsInitialized(ctx)
		Expect(err).NotTo(HaveOccurred())
		Expect(initialized).To(BeFalse())
	})

	It("should initialize from the gatekeeper and unseal", func() {
		keys, _, err = gk.InitializeBarrier(ctx, 5, 3)
		Expect(err).NotTo(HaveOccurred())
		Expect(keys).To(HaveLen(5))

		token, err = gk.GenerateGatekeeperTokenFromUnsealKeys(ctx, keys)
		Expect(err).NotTo(HaveOccurred())
		Expect(token).NotTo(BeEmpty())

		err = gk.UnsealWithUnsealKeys(ctx, keys[:2])
		Expect(err).To(HaveOccurred())

		err = gk.UnsealWithUnsealKeys(ctx, keys[:3])
		Expect(err).NotTo(HaveOccurred())

		sealed, err := barr.IsSealed(ctx)
		Expect(err).NotTo(HaveOccurred())
		Expect(sealed).To(BeFalse())
	})

	It("should have generated an accessKey", func() {
		item, err := barr.Get(ctx, accessKeyHashKey)
		Expect(err).NotTo(HaveOccurred())
		Expect(item).NotTo(BeNil())
		Expect(item.Raw).NotTo(BeEmpty())
	})

	It("should seal with a valid gatekeeper token", func() {
		err = gk.SealWithGatekeeperToken(ctx, token, false)
		Expect(err).NotTo(HaveOccurred())

		sealed, err := barr.IsSealed(ctx)
		Expect(err).NotTo(HaveOccurred())
		Expect(sealed).To(BeTrue())

		err = gk.UnsealWithGatekeeperToken(ctx, token, true)
		Expect(err).To(HaveOccurred())
	})

	It("should generate gatekeeper token from unseal keys", func() {
		token, err = gk.GenerateGatekeeperTokenFromUnsealKeys(ctx, keys)
		Expect(err).NotTo(HaveOccurred())

		err = gk.UnsealWithGatekeeperToken(ctx, token, true)
		Expect(err).NotTo(HaveOccurred())

		sealed, err := barr.IsSealed(ctx)
		Expect(err).NotTo(HaveOccurred())
		Expect(sealed).To(BeFalse())

		err = gk.SealWithGatekeeperToken(ctx, token, true)
		Expect(err).NotTo(HaveOccurred())
	})

	It("should rotate sharded unseal keys and remove existing gatekeeper tokens", func() {
		keys, err := gk.RotateUnsealKeys(ctx, keys, 5, 3)
		Expect(err).NotTo(HaveOccurred())
		Expect(keys).To(HaveLen(5))

		err = gk.UnsealWithGatekeeperToken(ctx, token, true)
		Expect(err).To(HaveOccurred())
	})

	It("should fail to initialize an already initialized barrier", func() {
		_, _, err = gk.InitializeBarrier(ctx, 5, 3)
		Expect(err).NotTo(BeNil())
		Expect(err).To(MatchError(barrier.ErrBarrierAlreadyInitialized))
	})

	It("should unseal again with new keys", func() {
		err := gk.UnsealWithUnsealKeys(ctx, keys)
		Expect(err).NotTo(HaveOccurred())

		sealed, err := barr.IsSealed(ctx)
		Expect(err).NotTo(HaveOccurred())
		Expect(sealed).To(BeFalse())
	})

	It("should generate an access token with correct access key", func() {
		item, err := barr.Get(ctx, accessKeyHashKey)
		Expect(err).NotTo(HaveOccurred())
		Expect(item).NotTo(BeNil())
		Expect(item.Raw).NotTo(BeEmpty())

		token, err := gk.tm.NewToken()
		Expect(err).NotTo(HaveOccurred())
		Expect(token).NotTo(BeNil())

		token.Acls = []*apiv1.ACL{
			{
				Path:        "/*",
				Permissions: []apiv1.Permission{apiv1.Permission_LIST, apiv1.Permission_READ},
			},
		}

		err = gk.SaveAccessTokenWithAccessKey(ctx, string(item.Raw), token)
		Expect(err).NotTo(HaveOccurred())
		Expect(token).NotTo(BeNil())
		Expect(gk.tm.IsTokenValid(token)).NotTo(HaveOccurred())
	})

	It("should fail to save an access token with bad access key", func() {
		token, err := gk.tm.NewToken()
		Expect(err).NotTo(HaveOccurred())
		Expect(token).NotTo(BeNil())

		err = gk.SaveAccessTokenWithAccessKey(ctx, string("not-gonna-happen"), token)
		Expect(err).To(MatchError(ErrInvalidAccessKey))
	})

	It("should rotate the access key", func() {
		item, err := barr.Get(ctx, accessKeyHashKey)
		Expect(err).NotTo(HaveOccurred())
		Expect(item).NotTo(BeNil())
		Expect(item.Raw).NotTo(BeEmpty())

		newAccessKey, err := gk.RotateAccessKey(ctx, string(item.Raw))
		Expect(err).NotTo(HaveOccurred())
		Expect(newAccessKey).NotTo(Equal(string(item.Raw)))
	})

	It("should rotate the access key with unseal keys", func() {
		item, err := barr.Get(ctx, accessKeyHashKey)
		Expect(err).NotTo(HaveOccurred())
		Expect(item).NotTo(BeNil())
		Expect(item.Raw).NotTo(BeEmpty())

		newAccessKey, err := gk.RotateAccessKeyWithUnsealKeys(ctx, keys)
		Expect(err).NotTo(HaveOccurred())
		Expect(newAccessKey).NotTo(Equal(string(item.Raw)))
	})
})
