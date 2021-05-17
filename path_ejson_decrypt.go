package secretsejson

import (
	"context"

	"github.com/hashicorp/errwrap"
	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

func ejsonDecryptPaths(b *backend) []*framework.Path {
	return []*framework.Path{
		&framework.Path{
			Pattern: "decrypt",
			Fields: map[string]*framework.FieldSchema{
				"document": &framework.FieldSchema{
					Type:        framework.TypeString,
					Description: "ejson document",
				},
			},
			Callbacks: map[logical.Operation]framework.OperationFunc{
				logical.CreateOperation: b.decrypt,
				logical.UpdateOperation: b.decrypt,
			},
		},
	}
}

func (b *backend) decrypt(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	inputData, ok := data.GetOk("ejson")
	if !ok {
		if len(data.Raw) == 0 {
			return logical.ErrorResponse("no data provided"), logical.ErrInvalidRequest
		}
		inputData = data.Raw
	}

	encData, err := MarshalInput(inputData)
	if err != nil {
		return nil, errwrap.Wrapf("failed to marshall json: {{err}}", err)
	}

	decData, err := DecryptEjsonDocument(ctx, req, encData)
	if err != nil {
		return nil, errwrap.Wrapf("failed to decrypt ejson: {{err}}", err)
	}

	return &logical.Response{
		Data: decData,
	}, nil
}
