package secretsejson

import (
	"context"
	"fmt"

	"github.com/Shopify/ejson"
	"github.com/hashicorp/errwrap"
	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

func ejsonKeysPaths(b *backend) []*framework.Path {
	return []*framework.Path{
		{
			Pattern: "keys/.*",
			Fields: map[string]*framework.FieldSchema{
				"public": &framework.FieldSchema{
					Type:        framework.TypeString,
					Description: "EJSON Public key",
				},
				"private": &framework.FieldSchema{
					Type:        framework.TypeString,
					Description: "EJSON Private key",
				},
			},
			ExistenceCheck: b.pathExistenceCheck,
			Callbacks: map[logical.Operation]framework.OperationFunc{
				logical.ReadOperation:   b.keyRead,
				logical.CreateOperation: b.keyCreateUpdate,
				logical.UpdateOperation: b.keyCreateUpdate,
				logical.DeleteOperation: b.keyDelete,
				logical.ListOperation:   b.keyList,
			},
		},
		{
			Pattern: "keypair",
			Callbacks: map[logical.Operation]framework.OperationFunc{
				logical.CreateOperation: b.keyPairCreate,
				logical.UpdateOperation: b.keyPairCreate,
			},
		},
	}
}

func (b *backend) pathExistenceCheck(ctx context.Context, req *logical.Request, data *framework.FieldData) (bool, error) {
	out, err := req.Storage.Get(ctx, req.Path)
	if err != nil {
		return false, errwrap.Wrapf("existence check failed: {{err}}", err)
	}

	return out != nil, nil
}

func (b *backend) keyRead(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	entry, err := req.Storage.Get(ctx, req.Path)
	if err != nil {
		return nil, err
	}

	if entry == nil {
		return nil, nil
	}

	b.Logger().Info("reading value at", "path", req.Path)
	// Return the secret
	resp := &logical.Response{
		Data: map[string]interface{}{
			"private": nil,
		},
	}

	resp.Data["private"] = string(entry.Value)

	return resp, nil
}

func (b *backend) keyCreateUpdate(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	private := data.Get("private").(string)

	b.Logger().Info("storing value at", "path", req.Path)
	entry := &logical.StorageEntry{
		Key:   req.Path,
		Value: []byte(private),
	}

	if err := req.Storage.Put(ctx, entry); err != nil {
		return nil, err
	}

	return &logical.Response{
		Data: map[string]interface{}{
			"private": private,
		},
	}, nil
}

func (b *backend) keyDelete(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	b.Logger().Info("deleting value at", "path", req.Path)
	if err := req.Storage.Delete(ctx, req.Path); err != nil {
		return nil, err
	}

	return nil, nil
}

func (b *backend) keyList(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	vals, err := req.Storage.List(ctx, req.Path)
	if err != nil {
		return nil, err
	}
	return logical.ListResponse(vals), nil
}

func (b *backend) keyPairCreate(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	public, private, err := ejson.GenerateKeypair()
	if err != nil {
		return nil, errwrap.Wrapf("failed to generate keypair ejson: {{err}}", err)
	}
	path := fmt.Sprintf("keys/%s", public)
	b.Logger().Info(fmt.Sprintf("New key pair at %s", path))
	entry := &logical.StorageEntry{
		Key:   path,
		Value: []byte(private),
	}
	if err := req.Storage.Put(ctx, entry); err != nil {
		return nil, err
	}

	return &logical.Response{
		Data: map[string]interface{}{
			"public": public,
		},
	}, nil
}
