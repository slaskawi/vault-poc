package v1

import (
	"context"

	apiv1 "github.com/slaskawi/vault-poc/api/v1"
)

// KVList will list the contents of the provided path.
func (s *KStash) KVList(ctx context.Context, req *apiv1.KVListRequest) (*apiv1.KVListResponse, error) {
	resp := &apiv1.KVListResponse{}

	token, err := s.CanToken(ctx, apiv1.Permission_LIST, req.Path)
	if err != nil {
		return resp, err
	}

	resp.Paths, err = s.gk.KV().List(ctx, token.Namespace, req.Path)
	if err != nil {
		return resp, err
	}

	return resp, nil
}

// KVGet will get an item from the provided path.
func (s *KStash) KVGet(ctx context.Context, req *apiv1.KVGetRequest) (*apiv1.KVGetResponse, error) {
	resp := &apiv1.KVGetResponse{}

	token, err := s.CanToken(ctx, apiv1.Permission_READ, req.Path)
	if err != nil {
		return resp, err
	}

	resp.Item, err = s.gk.KV().Get(ctx, token.Namespace, req.Path)
	if err != nil {
		return resp, err
	}

	return resp, nil
}

// KVPut will put an item in the provided path.
func (s *KStash) KVPut(ctx context.Context, req *apiv1.KVPutRequest) (*apiv1.KVPutResponse, error) {
	resp := &apiv1.KVPutResponse{}

	token, err := s.CanToken(ctx, apiv1.Permission_UPDATE, req.Item.Key)
	if err != nil {
		return resp, err
	}

	err = s.gk.KV().Put(ctx, token.Namespace, req.Item)
	return resp, err
}

// KVDelete will delete an item from the provided path.
func (s *KStash) KVDelete(ctx context.Context, req *apiv1.KVDeleteRequest) (*apiv1.KVDeleteResponse, error) {
	resp := &apiv1.KVDeleteResponse{}

	token, err := s.CanToken(ctx, apiv1.Permission_DELETE, req.Path)
	if err != nil {
		return resp, err
	}

	err = s.gk.KV().Delete(ctx, token.Namespace, req.Path)
	return resp, err
}
