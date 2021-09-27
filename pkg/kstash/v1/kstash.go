package v1

import (
	"context"
	"fmt"
	"strconv"
	"strings"
	"time"
	"unicode"

	"github.com/go-logr/logr"
	"google.golang.org/grpc/metadata"

	apiv1 "github.com/slaskawi/vault-poc/api/v1"
	"github.com/slaskawi/vault-poc/pkg/auth"
	"github.com/slaskawi/vault-poc/pkg/config"
	"github.com/slaskawi/vault-poc/pkg/gatekeeper"
	"github.com/slaskawi/vault-poc/pkg/secret/kv"
)

var (
	ErrInvalidTTL = fmt.Errorf("invalid TTL value")
)

type KStash struct {
	log logr.Logger
	gk  *gatekeeper.Gatekeeper

	apiv1.UnimplementedKStashServer
}

func NewKStash(log logr.Logger, conf *config.Config) (apiv1.KStashServer, error) {
	gk, err := conf.Gatekeeper(log)
	if err != nil {
		return nil, err
	}

	return &KStash{
		log: log,
		gk:  gk,
	}, nil
}

// GetTokenID from the given context. Returns an error if the token ID could not be found.
func (s *KStash) GetTokenID(ctx context.Context) (string, error) {
	meta, _ := metadata.FromIncomingContext(ctx)
	if meta == nil {
		return "", auth.ErrTokenNotFound
	}

	idS := meta.Get("authorization")
	if len(idS) == 0 {
		return "", auth.ErrTokenNotFound
	}

	return idS[0], nil
}

// GetToken from the given context. Returns an error if the token is invalid.
func (s *KStash) GetToken(ctx context.Context) (*apiv1.AccessToken, error) {
	id, err := s.GetTokenID(ctx)
	if err != nil {
		return nil, err
	}

	return s.gk.TokenManager().GetToken(ctx, id)
}

// CanToken determines if a token stored in the given context has the ACLs required to perform the desired operation.
// Returns the token, if found and an error if the token is not allowed to perform the requested operation.
func (s *KStash) CanToken(ctx context.Context, perm apiv1.Permission, path string) (*apiv1.AccessToken, error) {
	token, err := s.GetToken(ctx)
	if err != nil {
		return token, err
	}

	if len(token.Namespace) == 0 {
		return token, kv.ErrNoNamespace
	}

	return token, s.gk.ACLManager().CanPerform(token.Acls, perm, token.Namespace, path)
}

// ParseTTL attempts to parse the given TTL string. An example string to represent one hour would be `1h`.
// Other valid units of measure include `s` (seconds), `m` (minutes). If TTL has no unit of measure,
// seconds are assumed.
func (s *KStash) ParseTTL(ttl string) (time.Duration, error) {
	if len(ttl) == 0 {
		return 0, ErrInvalidTTL
	}

	if strings.IndexAny(ttl, "smh") == len(ttl)-1 {
		return time.ParseDuration(ttl)
	}

	if !unicode.IsDigit(rune(ttl[len(ttl)-1])) {
		return 0, ErrInvalidTTL
	}

	sec, err := strconv.ParseInt(ttl, 10, 64)
	if err != nil {
		return 0, fmt.Errorf("%w: %v", ErrInvalidTTL, err)
	}

	return time.Duration(sec * int64(time.Second)), nil
}
