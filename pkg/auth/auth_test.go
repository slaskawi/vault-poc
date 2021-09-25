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

var _ = Describe("token", func() {
	ctx := context.Background()

	back, err := memory.NewMemoryStorage(nil)
	Expect(err).NotTo(HaveOccurred())

	barr, err := barrier.NewBarrier(back)
	Expect(err).NotTo(HaveOccurred())

	gatekeeperKey, err := encryption.GenerateKey(apiv1.CipherType_AES256_GCM)
	Expect(err).NotTo(HaveOccurred())
	Expect(gatekeeperKey).NotTo(BeNil())

	err = barr.Initialize(ctx, gatekeeperKey, nil)
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

var _ = Describe("acls", func() {
	acls := []*apiv1.ACL{
		{
			Path:        "/*",
			Permissions: []apiv1.Permission{apiv1.Permission_LIST},
		},
		{
			Path:        "/test/kv/item1",
			Permissions: []apiv1.Permission{apiv1.Permission_READ},
		},
		{
			Path:        "/test/kv/folder1/*",
			Permissions: []apiv1.Permission{apiv1.Permission_LIST, apiv1.Permission_READ},
		},
		{
			Path:        "/test/kv/folder1/dropbox/*",
			Permissions: []apiv1.Permission{apiv1.Permission_CREATE},
		},
		{
			Path:        "/test/kv/folder1/deny/*",
			Permissions: []apiv1.Permission{apiv1.Permission_DENY},
		},
		{
			Path:        "/test/kv/folder1/item2",
			Permissions: []apiv1.Permission{apiv1.Permission_READ, apiv1.Permission_CREATE, apiv1.Permission_UPDATE},
		},
		{
			Path:        "/test/kv/folder1/denyItem",
			Permissions: []apiv1.Permission{apiv1.Permission_DENY},
		},
		{
			Path:        "/test/kv/myfolder/*",
			Permissions: []apiv1.Permission{apiv1.Permission_LIST, apiv1.Permission_READ, apiv1.Permission_CREATE, apiv1.Permission_UPDATE, apiv1.Permission_DELETE},
		},
	}

	expected := map[string][]apiv1.Permission{
		"/":                                       {apiv1.Permission_LIST},
		"foo/":                                    {apiv1.Permission_LIST},
		"/test/":                                  {apiv1.Permission_LIST},
		"/test/kv/":                               {apiv1.Permission_LIST},
		"/test/kv/item1":                          {apiv1.Permission_READ},
		"/test/kv/item2":                          {apiv1.Permission_LIST},
		"/test/kv/folder1/":                       {apiv1.Permission_LIST, apiv1.Permission_READ},
		"/test/kv/folder1/testItem":               {apiv1.Permission_LIST, apiv1.Permission_READ},
		"/test/kv/folder2":                        {apiv1.Permission_LIST},
		"/test/kv/folder1/dropbox":                {apiv1.Permission_LIST, apiv1.Permission_READ},
		"/test/kv/folder1/dropbox/":               {apiv1.Permission_CREATE},
		"/test/kv/folder1/dropbox/myitem":         {apiv1.Permission_CREATE},
		"/test/kv/folder1/denyItem":               {},
		"/test/kv/folder1/deny/":                  {},
		"/test/kv/folder1/deny/anyItem":           {},
		"/test/kv/folder1/item2":                  {apiv1.Permission_READ, apiv1.Permission_CREATE, apiv1.Permission_UPDATE},
		"/test/kv/myfolder/":                      {apiv1.Permission_LIST, apiv1.Permission_READ, apiv1.Permission_CREATE, apiv1.Permission_UPDATE, apiv1.Permission_DELETE},
		"/test/kv/myfolder/f1/f2/f3/f4/f5/myitem": {apiv1.Permission_LIST, apiv1.Permission_READ, apiv1.Permission_CREATE, apiv1.Permission_UPDATE, apiv1.Permission_DELETE},
	}

	am := NewACLManager()

	It("allows expected permissions", func() {
		for path, exPerms := range expected {
			perms, err := am.CalculatePermissions(acls, "", path)
			Expect(err).NotTo(HaveOccurred())
			Expect(perms).NotTo(BeNil())
			Expect(perms).To(ConsistOf(exPerms), path)
		}
	})

	It("allows expected permissions with a namespace", func() {
		for path, exPerms := range expected {
			perms, err := am.CalculatePermissions(acls, "/my/namespace/", path)
			Expect(err).NotTo(HaveOccurred())
			Expect(perms).NotTo(BeNil())
			Expect(perms).To(ConsistOf(exPerms), path)
		}
	})

	It("correctly reports if an action can be performed", func() {
		err := am.CanPerform(acls, apiv1.Permission_UPDATE, "", "/test/kv/folder1/item2")
		Expect(err).NotTo(HaveOccurred())
	})

	It("correctly reports if an action can be performed with namespace", func() {
		err := am.CanPerform(acls, apiv1.Permission_UPDATE, "/my/namespace", "/test/kv/folder1/item2")
		Expect(err).NotTo(HaveOccurred())
	})

	It("fail if path matches but permission is not allowed", func() {
		err := am.CanPerform(acls, apiv1.Permission_DELETE, "", "/test/kv/folder1/item2")
		Expect(err).To(MatchError(ErrForbidden))
	})

	It("fail if path matches but permission is not allowed with namespace", func() {
		err := am.CanPerform(acls, apiv1.Permission_DELETE, "/my/namespace", "/test/kv/folder1/item2")
		Expect(err).To(MatchError(ErrForbidden))
	})

	It("should cause a nil list of ACLs to forbid access", func() {
		var acls []*apiv1.ACL
		err := am.ValidateACLs(acls)
		Expect(err).NotTo(HaveOccurred())

		err = am.CanPerform(acls, apiv1.Permission_LIST, "", "/")
		Expect(err).To(MatchError(ErrForbidden))
	})

	It("should fail with misused wildcard", func() {
		acls := append(acls, &apiv1.ACL{
			Path:        "/test/*/",
			Permissions: []apiv1.Permission{apiv1.Permission_LIST},
		})
		err := am.ValidateACLs(acls)
		Expect(err).To(HaveOccurred())
	})

	It("should fail with a nil ACL", func() {
		acls := append(acls, nil)
		err := am.ValidateACLs(acls)
		Expect(err).To(HaveOccurred())
	})

	It("should fail with missing path", func() {
		acls := append(acls, &apiv1.ACL{
			Path:        "",
			Permissions: []apiv1.Permission{apiv1.Permission_LIST},
		})
		err := am.ValidateACLs(acls)
		Expect(err).To(HaveOccurred())
	})

	It("should fail with nil permissions", func() {
		acls := append(acls, &apiv1.ACL{
			Path:        "/test/",
			Permissions: nil,
		})
		err := am.ValidateACLs(acls)
		Expect(err).To(HaveOccurred())
	})

	It("should fail with zero permissions", func() {
		acls := append(acls, &apiv1.ACL{
			Path:        "/test/",
			Permissions: []apiv1.Permission{},
		})
		err := am.ValidateACLs(acls)
		Expect(err).To(HaveOccurred())
	})

	It("should fail if DENY is used with other permissions", func() {
		acls := append(acls, &apiv1.ACL{
			Path:        "/test/",
			Permissions: []apiv1.Permission{apiv1.Permission_DENY, apiv1.Permission_LIST},
		})
		err := am.ValidateACLs(acls)
		Expect(err).To(HaveOccurred())
	})
})
