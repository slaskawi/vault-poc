package v1

import (
	"context"
	"testing"
	"time"

	"github.com/go-logr/zapr"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	"go.uber.org/zap"
	"google.golang.org/grpc/metadata"

	apiv1 "github.com/slaskawi/vault-poc/api/v1"
	"github.com/slaskawi/vault-poc/pkg/auth"
	"github.com/slaskawi/vault-poc/pkg/barrier"
	"github.com/slaskawi/vault-poc/pkg/config"
	"github.com/slaskawi/vault-poc/pkg/gatekeeper"
	"github.com/slaskawi/vault-poc/pkg/secret/kv"
	"github.com/slaskawi/vault-poc/pkg/storage"
)

func TestKStash(t *testing.T) {
	defer GinkgoRecover()

	RegisterFailHandler(Fail)
	RunSpecs(t, "kstash")
}

var _ = Describe("kstash", func() {
	zapLog, _ := zap.NewDevelopment()
	log := zapr.NewLogger(zapLog)
	conf := config.Get()
	ctx := context.Background()

	server, err := NewKStash(log, conf)
	Expect(err).NotTo(HaveOccurred())
	Expect(server).NotTo(BeNil())

	ks := server.(*KStash)

	var (
		accessKey       string
		gatekeeperToken string
		unsealKeys      []string
		token           *apiv1.AccessToken
	)

	It("checks the status of an uninitialized barrier", func() {
		req := &apiv1.SystemStatusRequest{}
		resp, err := server.SystemStatus(ctx, req)
		Expect(err).NotTo(HaveOccurred())
		Expect(resp).NotTo(BeNil())
		Expect(resp.Initialized).To(BeFalse())
		Expect(resp.Sealed).To(BeTrue())
		Expect(resp.ServerTimestamp.Seconds).NotTo(BeZero())
	})

	It("initializes an uninitialized barrier", func() {
		req := &apiv1.SystemInitializeRequest{
			NumUnsealKeys:           5,
			UnsealKeyThreshold:      3,
			GenerateGatekeeperToken: true,
		}

		resp, err := server.SystemInitialize(ctx, req)
		Expect(err).NotTo(HaveOccurred())
		Expect(resp).NotTo(BeNil())
		Expect(resp.AccessKey).NotTo(BeEmpty())
		Expect(resp.GatekeeperToken).NotTo(BeEmpty())
		Expect(resp.UnsealKeys).To(HaveLen(5))

		accessKey = resp.AccessKey
		gatekeeperToken = resp.GatekeeperToken
		unsealKeys = resp.UnsealKeys
	})

	It("can unseal the barrier with unseal keys", func() {
		req := &apiv1.SystemUnsealRequest{
			UnsealKeys: unsealKeys,
		}

		resp, err := server.SystemUnseal(ctx, req)
		Expect(err).NotTo(HaveOccurred())
		Expect(resp.Sealed).To(BeFalse())
	})

	It("can seal the barrier", func() {
		req := &apiv1.SystemSealRequest{
			GatekeeperToken: gatekeeperToken,
			Renew:           true,
		}

		resp, err := server.SystemSeal(ctx, req)
		Expect(err).NotTo(HaveOccurred())
		Expect(resp).NotTo(BeNil())
		Expect(resp.Sealed).To(BeTrue())
	})

	It("won't unseal with wrong number of unseal keys", func() {
		req := &apiv1.SystemUnsealRequest{
			UnsealKeys: unsealKeys[:2],
		}

		resp, err := server.SystemUnseal(ctx, req)
		Expect(err).To(MatchError(barrier.ErrBarrierInvalidKey))
		Expect(resp).NotTo(BeNil())
	})

	It("won't unseal with invalid gatekeeper token", func() {
		req := &apiv1.SystemUnsealRequest{
			GatekeeperToken:      "wont-work",
			RenewGatekeeperToken: true,
		}

		resp, err := server.SystemUnseal(ctx, req)
		Expect(err).To(MatchError(gatekeeper.ErrInvalidGatekeeperToken))
		Expect(resp).NotTo(BeNil())
	})

	It("checks the status of a sealed barrier", func() {
		req := &apiv1.SystemStatusRequest{}
		resp, err := server.SystemStatus(ctx, req)
		Expect(err).NotTo(HaveOccurred())
		Expect(resp).NotTo(BeNil())
		Expect(resp.Initialized).To(BeTrue())
		Expect(resp.Sealed).To(BeTrue())
		Expect(resp.ServerTimestamp.Seconds).NotTo(BeZero())
	})

	It("can unseal the barrier with gatekeeper token", func() {
		req := &apiv1.SystemUnsealRequest{
			GatekeeperToken:      gatekeeperToken,
			RenewGatekeeperToken: true,
		}

		resp, err := server.SystemUnseal(ctx, req)
		Expect(err).NotTo(HaveOccurred())
		Expect(resp.Sealed).To(BeFalse())
	})

	It("can seal the barrier without renewing the gatekeeper token", func() {
		req := &apiv1.SystemSealRequest{
			GatekeeperToken: gatekeeperToken,
			Renew:           false,
		}

		resp, err := server.SystemSeal(ctx, req)
		Expect(err).NotTo(HaveOccurred())
		Expect(resp).NotTo(BeNil())
		Expect(resp.Sealed).To(BeTrue())
	})

	It("checks that a non-renewed gatekeeper token is revoked", func() {
		req := &apiv1.SystemUnsealRequest{
			GatekeeperToken: gatekeeperToken,
		}

		resp, err := server.SystemUnseal(ctx, req)
		Expect(err).To(MatchError(gatekeeper.ErrInvalidGatekeeperToken))
		Expect(resp).NotTo(BeNil())
	})

	It("can generate a new gatekeeper token from unseal keys", func() {
		req := &apiv1.SystemGenerateGatekeeperTokenRequest{
			UnsealKeys: unsealKeys,
		}

		resp, err := server.SystemGenerateGatekeeperToken(ctx, req)
		Expect(err).NotTo(HaveOccurred())
		Expect(resp).NotTo(BeNil())
		Expect(resp.GatekeeperToken).NotTo(BeEmpty())
		Expect(resp.GatekeeperToken).NotTo(Equal(gatekeeperToken))

		gatekeeperToken = resp.GatekeeperToken
	})

	It("can rotate the gatekeeper token", func() {
		req := &apiv1.SystemRotateGatekeeperTokenRequest{
			GatekeeperToken: gatekeeperToken,
		}

		resp, err := server.SystemRotateGatekeeperToken(ctx, req)
		Expect(err).NotTo(HaveOccurred())
		Expect(resp).NotTo(BeNil())
		Expect(resp.GatekeeperToken).NotTo(Equal(gatekeeperToken))

		gatekeeperToken = resp.GatekeeperToken
	})

	It("can unseal the barrier again with unseal tokens", func() {
		req := &apiv1.SystemUnsealRequest{
			UnsealKeys: unsealKeys,
		}

		resp, err := server.SystemUnseal(ctx, req)
		Expect(err).NotTo(HaveOccurred())
		Expect(resp.Sealed).To(BeFalse())
	})

	It("can rotate the encryption key", func() {
		req := &apiv1.SystemRotateEncryptionKeyRequest{
			GatekeeperToken: gatekeeperToken,
			Renew:           true,
		}

		resp, err := server.SystemRotateEncryptionKey(ctx, req)
		Expect(err).NotTo(HaveOccurred())
		Expect(resp).NotTo(BeNil())
	})

	It("can revoke the gatekeeper token", func() {
		req := &apiv1.SystemRevokeGatekeeperTokenRequest{
			GatekeeperToken: gatekeeperToken,
		}

		resp, err := server.SystemRevokeGatekeeperToken(ctx, req)
		Expect(err).NotTo(HaveOccurred())
		Expect(resp).NotTo(BeNil())
	})

	It("can rotate the access key", func() {
		req := &apiv1.SystemRotateAccessKeyRequest{
			AccessKey: accessKey,
		}

		resp, err := server.SystemRotateAccessKey(ctx, req)
		Expect(err).NotTo(HaveOccurred())
		Expect(resp).NotTo(BeNil())
		Expect(resp.AccessKey).NotTo(BeZero())

		accessKey = resp.AccessKey
	})

	It("can rotate the unseal keys", func() {
		req := &apiv1.SystemRotateUnsealKeysRequest{
			UnsealKeys:         unsealKeys,
			NumUnsealKeys:      5,
			UnsealKeyThreshold: 3,
		}

		resp, err := server.SystemRotateUnsealKeys(ctx, req)
		Expect(err).NotTo(HaveOccurred())
		Expect(resp).NotTo(BeNil())
		Expect(resp.UnsealKeys).NotTo(ContainElements(unsealKeys))

		unsealKeys = resp.UnsealKeys
	})

	It("can generate a access token from access key", func() {
		req := &apiv1.SystemGenerateAccessTokenRequest{
			AccessKey: accessKey,
			Namespace: "test",
			ExpiresAt: time.Now().Add(time.Minute).Unix(),
			Acls: []*apiv1.ACL{
				{
					Path: "/*",
					Permissions: []apiv1.Permission{
						apiv1.Permission_LIST,
						apiv1.Permission_READ,
						apiv1.Permission_CREATE,
						apiv1.Permission_UPDATE,
						apiv1.Permission_DELETE,
					},
				},
				{
					Path: "deny/*",
					Permissions: []apiv1.Permission{
						apiv1.Permission_DENY,
					},
				},
			},
		}

		resp, err := server.SystemGenerateAccessToken(ctx, req)
		Expect(err).NotTo(HaveOccurred())
		Expect(resp).NotTo(BeNil())
		Expect(resp.Token).NotTo(BeNil())
		Expect(resp.Token.Id).NotTo(BeEmpty())

		token = resp.Token
	})

	It("can validate token", func() {
		err := ks.gk.TokenManager().IsTokenValid(token)
		Expect(err).NotTo(HaveOccurred())

		am := auth.NewACLManager()
		err = am.ValidateACLs(token.Acls)
		Expect(err).NotTo(HaveOccurred())

		err = am.CanPerform(token.Acls, apiv1.Permission_CREATE, "test", "folder1/key1")
		Expect(err).NotTo(HaveOccurred())
	})

	It("can renew token", func() {
		req := &apiv1.AuthTokenRenewRequest{
			TokenID: token.Id,
			Ttl:     "1m",
		}

		resp, err := server.AuthTokenRenew(ctx, req)
		Expect(err).NotTo(HaveOccurred())
		Expect(resp).NotTo(BeNil())
		Expect(resp.Token.ExpiresAt == token.ExpiresAt).To(BeTrue())
	})

	It("can get token info", func() {
		req := &apiv1.AuthTokenLookupRequest{
			TokenID: token.Id,
		}

		resp, err := server.AuthTokenLookup(ctx, req)
		Expect(err).NotTo(HaveOccurred())
		Expect(resp).NotTo(BeNil())
		Expect(resp.Token.ExpiresAt == token.ExpiresAt).To(BeTrue())
		Expect(resp.Token.Id).To(Equal(token.Id))
		Expect(resp.Token.ReferenceID).To(Equal(token.ReferenceID))
		Expect(resp.Token.Namespace).To(Equal(token.Namespace))
	})

	It("fails to find a token in an empty context", func() {
		req := &apiv1.KVListRequest{}
		_, err := server.KVList(ctx, req)
		Expect(err).To(MatchError(auth.ErrTokenNotFound))
	})

	It("fails to find a token in a context with empty metadata", func() {
		ctx := metadata.NewIncomingContext(ctx, metadata.Pairs("authorization", ""))
		req := &apiv1.KVListRequest{}
		_, err := server.KVList(ctx, req)
		Expect(err).To(MatchError(auth.ErrTokenNotFound))
	})

	It("fails to validate a token that is too short in a context", func() {
		ctx := metadata.NewIncomingContext(ctx, metadata.Pairs("authorization", "1234"))
		req := &apiv1.KVListRequest{}
		_, err := server.KVList(ctx, req)
		Expect(err).To(MatchError(auth.ErrTokenNotFound))
	})

	It("fails to validate a bad token without Bearer in a context", func() {
		ctx := metadata.NewIncomingContext(ctx, metadata.Pairs("authorization", "1234567890"))
		req := &apiv1.KVListRequest{}
		_, err := server.KVList(ctx, req)
		Expect(err).To(MatchError(auth.ErrTokenInvalid))
	})

	It("fails to validate a bad token in a context", func() {
		ctx := metadata.NewIncomingContext(ctx, metadata.Pairs("authorization", "Bearer 1234567890"))
		req := &apiv1.KVListRequest{}
		_, err := server.KVList(ctx, req)
		Expect(err).To(MatchError(auth.ErrTokenInvalid))
	})

	It("fails to operate on the kv without a namespace in the token", func() {
		req := &apiv1.SystemGenerateAccessTokenRequest{
			AccessKey: accessKey,
			ExpiresAt: time.Now().Add(time.Minute).Unix(),
		}

		resp, err := server.SystemGenerateAccessToken(ctx, req)
		Expect(err).NotTo(HaveOccurred())
		Expect(resp).NotTo(BeNil())
		Expect(resp.Token).NotTo(BeNil())
		Expect(resp.Token.Id).NotTo(BeEmpty())

		ctx := metadata.NewIncomingContext(ctx, metadata.Pairs("authorization", "Bearer "+resp.Token.Id))
		req2 := &apiv1.KVListRequest{}
		_, err = server.KVList(ctx, req2)
		Expect(err).To(MatchError(kv.ErrNoNamespace))
	})

	It("can put an item in the kv", func() {
		req := &apiv1.KVPutRequest{
			Item: &apiv1.Item{
				Key: "folder1/item1",
				Raw: []byte("the-data"),
			},
		}

		ctx = metadata.NewIncomingContext(ctx, metadata.Pairs("authorization", "Bearer "+token.Id))
		resp, err := server.KVPut(ctx, req)
		Expect(err).NotTo(HaveOccurred())
		Expect(resp).NotTo(BeNil())
	})

	It("can list items in the kv", func() {
		req := &apiv1.KVListRequest{
			Path: "folder1",
		}

		resp, err := server.KVList(ctx, req)
		Expect(err).NotTo(HaveOccurred())
		Expect(resp).NotTo(BeNil())
		Expect(resp.Paths).To(HaveLen(1))
		Expect(resp.Paths[0]).To(Equal("item1"))
	})

	It("can get an item in the kv", func() {
		req := &apiv1.KVGetRequest{
			Path: "folder1/item1",
		}

		resp, err := server.KVGet(ctx, req)
		Expect(err).NotTo(HaveOccurred())
		Expect(resp).NotTo(BeNil())
		Expect(resp.Item).NotTo(BeNil())
		Expect(resp.Item.Key).To(Equal("folder1/item1"))
		Expect(resp.Item.Raw).To(Equal([]byte("the-data")))
	})

	It("can delete an item in the kv", func() {
		req := &apiv1.KVDeleteRequest{
			Path: "folder1/item1",
		}

		resp, err := server.KVDelete(ctx, req)
		Expect(err).NotTo(HaveOccurred())
		Expect(resp).NotTo(BeNil())
	})

	It("fails to get an item that was deleted", func() {
		req := &apiv1.KVGetRequest{
			Path: "folder1/item1",
		}

		resp, err := server.KVGet(ctx, req)
		Expect(err).To(MatchError(storage.ErrNotFound))
		Expect(resp).NotTo(BeNil())
	})

	It("can revoke token", func() {
		req := &apiv1.AuthTokenRevokeRequest{
			TokenID: token.Id,
		}

		resp, err := server.AuthTokenRevoke(ctx, req)
		Expect(err).NotTo(HaveOccurred())
		Expect(resp).NotTo(BeNil())
	})

	It("fails to get info on token that was revoked", func() {
		req := &apiv1.AuthTokenLookupRequest{
			TokenID: token.Id,
		}

		resp, err := server.AuthTokenLookup(ctx, req)
		Expect(err).To(MatchError(auth.ErrTokenNotFound))
		Expect(resp).NotTo(BeNil())
	})

	It("prunes expired tokens", func() {
		t, err := ks.gk.TokenManager().NewToken()
		Expect(err).NotTo(HaveOccurred())
		Expect(t).NotTo(BeNil())
		Expect(t.Id).NotTo(BeEmpty())
		Expect(t.ReferenceID).NotTo(BeEmpty())

		t.ExpiresAt = 1
		err = ks.gk.TokenManager().SaveToken(ctx, t)
		Expect(err).NotTo(HaveOccurred())

		req := &apiv1.SystemPruneTokensRequest{
			AccessKey: accessKey,
		}

		resp, err := server.SystemPruneTokens(ctx, req)
		Expect(err).NotTo(HaveOccurred())
		Expect(resp).NotTo(BeNil())

		t, err = ks.gk.TokenManager().GetTokenByReferenceID(ctx, t.ReferenceID)
		Expect(err).To(MatchError(auth.ErrTokenNotFound))
		Expect(t).To(BeNil())
	})

	It("fails to prune tokens if access key is invalid", func() {
		req := &apiv1.SystemPruneTokensRequest{
			AccessKey: accessKey[1:],
		}

		resp, err := server.SystemPruneTokens(ctx, req)
		Expect(err).To(MatchError(gatekeeper.ErrInvalidAccessKey))
		Expect(resp).NotTo(BeNil())
	})

	It("can parse the TTL", func() {
		d, err := ks.ParseTTL("")
		Expect(err).To(MatchError(ErrInvalidTTL))
		Expect(d).To(BeZero())

		d, err = ks.ParseTTL("1d")
		Expect(err).To(MatchError(ErrInvalidTTL))
		Expect(d).To(BeZero())

		d, err = ks.ParseTTL("asdf")
		Expect(err).To(MatchError(ErrInvalidTTL))
		Expect(d).To(BeZero())

		d, err = ks.ParseTTL("asdf50")
		Expect(err).To(MatchError(ErrInvalidTTL))
		Expect(d).To(BeZero())

		d, err = ks.ParseTTL("1h")
		Expect(err).NotTo(HaveOccurred())
		Expect(d).To(Equal(time.Hour))

		d, err = ks.ParseTTL("5m")
		Expect(err).NotTo(HaveOccurred())
		Expect(d).To(Equal(5 * time.Minute))

		d, err = ks.ParseTTL("300")
		Expect(err).NotTo(HaveOccurred())
		Expect(d).To(Equal(5 * time.Minute))
	})
})
