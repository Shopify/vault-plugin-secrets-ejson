package secretsejson

import (
	"context"
	"fmt"

	"github.com/hashicorp/errwrap"
	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

func ejsonIdentityPath(b *backend) []*framework.Path {
	return []*framework.Path{
		&framework.Path{
			Pattern: "identity",
			Fields: map[string]*framework.FieldSchema{
				"plaintext": &framework.FieldSchema{
					Type:        framework.TypeString,
					Description: "plaintext string to get identity for",
				},
			},
			ExistenceCheck: b.pathExistenceCheck,
			Callbacks: map[logical.Operation]framework.OperationFunc{
				logical.ReadOperation: b.HashPlaintext,
			},
		},
	}
}

func (b *backend) HashPlaintext(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	plaintext := data.Get("plaintext").(string)

	salt := b.IdentitySaltOrDefault(ctx, req)

	identity, err := HashPlaintext([]byte(plaintext), salt)
	if err != nil {
		return nil, errwrap.Wrapf("failed to decrypt ejson: {{err}}", err)
	}
	return &logical.Response{
		Data: map[string]interface{}{
			"identity": fmt.Sprintf("%x", identity),
		},
	}, nil
}
