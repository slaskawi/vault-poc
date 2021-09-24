package auth

import (
	"context"
	"testing"
	"time"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"

	apiv1 "github.com/slaskawi/vault-poc/api/v1"
	"github.com/slaskawi/vault-poc/pkg/barrier"
	"github.com/slaskawi/vault-poc/pkg/barrier/encryption"
	"github.com/slaskawi/vault-poc/pkg/storage/memory"
)

func TestAuth(t *testing.T) {
	defer GinkgoRecover()

	RegisterFailHandler(Fail)
	RunSpecs(t, "auth")
}

var _ = Describe("auth", func() {
	ctx := context.Background()

	back, err := memory.NewMemoryStorage(nil)
	Expect(err).NotTo(HaveOccurred())

	barr, err := barrier.NewBarrier(back)
	Expect(err).NotTo(HaveOccurred())

	gatekeeperKey, err := encryption.GenerateKey(apiv1.CipherType_AES256_GCM)
	Expect(err).NotTo(HaveOccurred())
	Expect(gatekeeperKey).NotTo(BeNil())

	err = barr.Initialize(ctx, gatekeeperKey)
	Expect(err).NotTo(HaveOccurred())

	err = barr.Unseal(ctx, gatekeeperKey)
	Expect(err).NotTo(HaveOccurred())

	tm := NewTokenManager(barr)
	var token *apiv1.AccessToken

	It("can create a new token", func() {
		token, err = tm.NewToken()
		Expect(err).NotTo(HaveOccurred())
		Expect(token).NotTo(BeNil())
		Expect(token.Id).To(HaveLen(TokenLength))
		Expect(token.Id).To(HavePrefix(tokenIDPrefix))
		Expect(token.ReferenceID).To(HaveLen(TokenLength))
		Expect(token.ReferenceID).To(HavePrefix(tokenReferenceIDPrefix))
		Expect(token.CreatedAt).NotTo(BeZero())
	})

	It("can save a token", func() {
		err = tm.SaveToken(ctx, token)
		Expect(err).NotTo(HaveOccurred())
	})

	It("can get the token by referenceID", func() {
		t, err := tm.GetTokenByReferenceID(ctx, token.ReferenceID)
		Expect(err).NotTo(HaveOccurred())
		Expect(t).NotTo(BeNil())
		Expect(t.ReferenceID).To(Equal(token.ReferenceID))
	})

	It("can get the token by its ID", func() {
		t, err := tm.GetToken(ctx, token.Id)
		Expect(err).NotTo(HaveOccurred())
		Expect(t).NotTo(BeNil())
		Expect(t.Id).To(Equal(token.Id))
		Expect(t.CreatedAt).NotTo(BeZero())
		Expect(t.EnabledAt).To(BeZero())
		Expect(t.ExpiresAt > time.Now().Unix()).To(BeTrue())

		err = tm.IsTokenValid(token)
		Expect(err).NotTo(HaveOccurred())
	})

	It("fails to get a token with the wrong length", func() {
		_, err := tm.GetToken(ctx, "1234567890")
		Expect(err).To(HaveOccurred())
		Expect(err).To(MatchError(ErrTokenInvalid))
	})

	It("fails to get a token by referenceID with the wrong length", func() {
		_, err := tm.GetTokenByReferenceID(ctx, "1234567890")
		Expect(err).To(HaveOccurred())
		Expect(err).To(MatchError(ErrTokenInvalid))
	})

	It("fails to get a token that doesn't exist", func() {
		_, err := tm.GetToken(ctx, tokenIDPrefix+"1234567890abcedfgh")
		Expect(err).To(HaveOccurred())
		Expect(err).To(MatchError(ErrTokenNotFound))
	})

	It("fails to get a token by reference that doesn't exist", func() {
		_, err := tm.GetTokenByReferenceID(ctx, tokenReferenceIDPrefix+"1234567890abcedfgh")
		Expect(err).To(HaveOccurred())
		Expect(err).To(MatchError(ErrTokenNotFound))
	})

	It("fails to get an expired token", func() {
		token.ExpiresAt = 1
		err = tm.SaveToken(ctx, token)
		Expect(err).NotTo(HaveOccurred())

		t, err := tm.GetToken(ctx, token.Id)
		Expect(err).To(HaveOccurred())
		Expect(err).To(MatchError(ErrTokenNotFound))
		Expect(t).NotTo(BeNil())
	})

	It("fails to get an token that isn't active yet", func() {
		token.ExpiresAt = 0
		token.EnabledAt = time.Now().Add(time.Hour).Unix()
		err = tm.SaveToken(ctx, token)
		Expect(err).NotTo(HaveOccurred())

		t, err := tm.GetToken(ctx, token.Id)
		Expect(err).To(HaveOccurred())
		Expect(err).To(MatchError(ErrTokenNotActiveYet))
		Expect(t).NotTo(BeNil())
	})

	It("revokes a token", func() {
		err = tm.RevokeToken(ctx, token.Id)
		Expect(err).NotTo(HaveOccurred())

		t, err := tm.GetToken(ctx, token.Id)
		Expect(err).To(HaveOccurred())
		Expect(err).To(MatchError(ErrTokenNotFound))
		Expect(t).To(BeNil())
	})

	It("can renew a token", func() {
		token, err = tm.NewToken()
		Expect(err).NotTo(HaveOccurred())

		err = tm.SaveToken(ctx, token)
		Expect(err).NotTo(HaveOccurred())

		token, err = tm.GetTokenByReferenceID(ctx, token.ReferenceID)
		Expect(err).NotTo(HaveOccurred())
		Expect(token).NotTo(BeNil())

		t, err := tm.RenewTokenByReferenceID(ctx, token.ReferenceID, 4*time.Hour)
		Expect(err).NotTo(HaveOccurred())
		Expect(t).NotTo(BeNil())
		Expect(t.ExpiresAt > token.ExpiresAt).To(BeTrue())
	})
})
