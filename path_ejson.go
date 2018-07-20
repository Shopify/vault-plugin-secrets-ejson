package mock

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"

	"github.com/Shopify/ejson"
	ej "github.com/Shopify/ejson/json"

	"github.com/hashicorp/errwrap"
	"github.com/hashicorp/vault/logical"
	"github.com/hashicorp/vault/logical/framework"
)

func ejsonPaths(b *backend) []*framework.Path {
	return []*framework.Path{
		&framework.Path{
			Pattern: ".*",
			Fields: map[string]*framework.FieldSchema{
				"ejson": &framework.FieldSchema{
					Type:        framework.TypeMap,
					Description: "EJSON document",
				},
			},
			ExistenceCheck: b.pathExistenceCheck,
			Callbacks: map[logical.Operation]framework.OperationFunc{
				logical.ReadOperation:   b.ejsonRead,
				logical.CreateOperation: b.ejsonCreateUpdate,
				logical.UpdateOperation: b.ejsonCreateUpdate,
				logical.DeleteOperation: b.ejsonDelete,
				logical.ListOperation:   b.ejsonList,
			},
		},
	}
}

func (b *backend) ejsonRead(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
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
			"ejson": nil,
		},
	}

	vData := map[string]interface{}{}
	if err := json.Unmarshal([]byte(entry.Value), &vData); err != nil {
		return nil, err
	}

	resp.Data["ejson"] = vData

	return resp, nil
}

func (b *backend) ejsonCreateUpdate(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	var inputData interface{}
	var encData []byte
	var out bytes.Buffer
	var err error

	inputData, ok := data.GetOk("ejson")
	if !ok {
		if len(data.Raw) == 0 {
			return logical.ErrorResponse("no data provided"), logical.ErrInvalidRequest
		}
		inputData = data.Raw
	}

	switch value := inputData.(type) {
	case map[string]interface{}:
		encData, err = json.Marshal(value)
		if err != nil {
			return nil, err
		}
	default:
		return logical.ErrorResponse("data provided was in an unexpected format"), logical.ErrInvalidRequest
	}

	pubKey, err := ej.ExtractPublicKey(encData)
	if err != nil {
		return nil, errwrap.Wrapf("failed to extract public key: {{err}}", err)
	}

	// Find the matching public key in keys/
	keyPair, err := req.Storage.Get(ctx, fmt.Sprintf("keys/%x", pubKey))
	if err != nil {
		return nil, errwrap.Wrapf("failed to find public key in keys/: {{err}}", err)
	}

	if err := ejson.Decrypt(bytes.NewBuffer(encData), &out, "", string(keyPair.Value)); err != nil {
		return nil, errwrap.Wrapf("failed to decrypt ejson: {{err}}", err)
	}

	// Remove the _public_key key so it doesn't end up as a value
	decData := map[string]interface{}{}
	if err := json.Unmarshal(out.Bytes(), &decData); err != nil {
		return nil, err
	}
	delete(decData, "_public_key")

	// Marshal the sanitized values one last time so we can store it
	sanData, err := json.Marshal(decData)
	if err != nil {
		return nil, errwrap.Wrapf("failed to marshall sanitized json: {{err}}", err)
	}

	b.Logger().Info("storing encrypted value at", "path", req.Path)
	encEntry := &logical.StorageEntry{
		Key:   req.Path,
		Value: encData,
	}
	if err := req.Storage.Put(ctx, encEntry); err != nil {
		return nil, err
	}

	b.Logger().Info("storing decrypted value at", "path", fmt.Sprintf("%s/decrypted", req.Path))
	decEntry := &logical.StorageEntry{
		Key:   fmt.Sprintf("%s/decrypted", req.Path),
		Value: sanData,
	}
	if err := req.Storage.Put(ctx, decEntry); err != nil {
		return nil, err
	}

	return &logical.Response{
		Data: map[string]interface{}{
			"ejson": inputData,
		},
	}, nil
}

func (b *backend) ejsonDelete(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	b.Logger().Info("deleting value at", "path", req.Path)
	if err := req.Storage.Delete(ctx, req.Path); err != nil {
		return nil, err
	}

	b.Logger().Info("deleting value at", "path", fmt.Sprintf("%s/decrypted", req.Path))
	if err := req.Storage.Delete(ctx, fmt.Sprintf("%s/decrypted", req.Path)); err != nil {
		return nil, err
	}

	return nil, nil
}

func (b *backend) ejsonList(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	vals, err := req.Storage.List(ctx, req.Path)
	if err != nil {
		return nil, err
	}
	return logical.ListResponse(vals), nil
}
