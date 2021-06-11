package secretsejson

import (
	"context"
	"fmt"

	"github.com/Shopify/ejson"
	ej "github.com/Shopify/ejson/json"
	"github.com/hashicorp/errwrap"
	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

func ejsonRotatePaths(b *backend) []*framework.Path {
	return []*framework.Path{
		&framework.Path{
			Pattern: "rotate",
			Fields: map[string]*framework.FieldSchema{
				"document": &framework.FieldSchema{
					Type:        framework.TypeString,
					Description: "EJSON Document",
				},
			},
			Callbacks: map[logical.Operation]framework.OperationFunc{
				logical.CreateOperation: b.rotate,
				logical.UpdateOperation: b.rotate,
			},
		},
	}
}

func (b *backend) rotate(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	inputData, ok := data.GetOk("document")
	if !ok {
		if len(data.Raw) == 0 {
			return logical.ErrorResponse("no data provided"), logical.ErrInvalidRequest
		}
		inputData = data.Raw
	}

	encData, err := MarshalInput(inputData)
	if err != nil {
		return nil, errwrap.Wrapf("failed to marshal json: {{err}}", err)
	}

	decDoc, err := DecryptEjsonDocument(ctx, req, encData)
	if err != nil {
		return nil, errwrap.Wrapf("failed to decrypt ejson: {{err}}", err)
	}

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

	oldPublicKey := decDoc[ej.PublicKeyField].(string)
	decDoc[ej.PublicKeyField] = public

	encDoc, err := EncryptEjsonDocument(ctx, decDoc)
	if err != nil {
		return nil, fmt.Errorf("failed to encrypt ejson")
	}

	return &logical.Response{
		Data: map[string]interface{}{
			"old_public_key": oldPublicKey,
			"new_public_key": public,
			"document":       encDoc,
		},
	}, nil
}
