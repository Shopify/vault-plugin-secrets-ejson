package secretsejson

import (
	"context"
	"fmt"

	ej "github.com/Shopify/ejson/json"
	"github.com/hashicorp/errwrap"
	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

func ejsonCopyPaths(b *backend) []*framework.Path {
	return []*framework.Path{
		{
			Pattern: "copy",
			Fields: map[string]*framework.FieldSchema{
				"document": {
					Type:        framework.TypeString,
					Description: "EJSON Document",
				},
				"public_key": {
					Type:        framework.TypeString,
					Description: "EJSON Public Key",
				},
			},
			Callbacks: map[logical.Operation]framework.OperationFunc{
				logical.UpdateOperation: b.copy,
			},
		},
	}
}

func (b *backend) copy(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	documentData, ok := data.GetOk("document")
	if !ok {
		return logical.ErrorResponse("no document data provided"), logical.ErrInvalidRequest
	}

	encData, err := MarshalInput(documentData)
	if err != nil {
		return nil, errwrap.Wrapf("failed to marshal json: {{err}}", err)
	}

	decDoc, err := DecryptEjsonDocument(ctx, req, encData)
	if err != nil {
		return nil, err
	}

	publicKeyData, ok := data.GetOk("public_key")
	if !ok {
		return logical.ErrorResponse("no public key data provided"), logical.ErrInvalidRequest
	}

	path := fmt.Sprintf("keys/%s", publicKeyData)
	b.Logger().Info(fmt.Sprintf("Encrypting with key pair at %s", path))

	keyPair, err := req.Storage.Get(ctx, path)
	if err != nil {
		return nil, fmt.Errorf("failed to find keypair at path %s: %s", path, err)
	}
	if keyPair == nil {
		return nil, fmt.Errorf("failed to find keypair in %s", path)
	}

	decDoc[ej.PublicKeyField] = publicKeyData

	encDoc, err := EncryptEjsonDocument(ctx, decDoc)
	if err != nil {
		return nil, fmt.Errorf("failed to encrypt ejson")
	}

	return &logical.Response{
		Data: map[string]interface{}{
			"document": encDoc,
		},
	}, nil
}
