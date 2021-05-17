package secretsejson

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"

	"github.com/Shopify/ejson"
	ej "github.com/Shopify/ejson/json"
	"github.com/hashicorp/vault/sdk/logical"
)

func DecryptEjsonDocument(ctx context.Context, req *logical.Request, encData []byte) (map[string]interface{}, error) {
	var out bytes.Buffer
	var err error

	pubKey, err := ej.ExtractPublicKey(encData)
	if err != nil {
		return nil, fmt.Errorf("failed to extract public key: %s", err)
	}

	// Find the matching public key in keys/
	keyPair, err := req.Storage.Get(ctx, fmt.Sprintf("keys/%x", pubKey))
	if err != nil {
		return nil, fmt.Errorf("failed to find public key in keys/: %s", err)
	}

	if err := ejson.Decrypt(bytes.NewBuffer(encData), &out, "", string(keyPair.Value)); err != nil {
		return nil, fmt.Errorf("failed to decrypt ejson: %s", err)
	}
	decData := map[string]interface{}{}
	if err := json.Unmarshal(out.Bytes(), &decData); err != nil {
		return nil, err
	}

	return decData, nil
}

func MarshalInput(inputData interface{}) ([]byte, error) {
	switch value := inputData.(type) {
	case map[string]interface{}:
		encData, err := json.Marshal(value)
		if err != nil {
			return nil, err
		}
		return encData, nil
	default:
		return nil, fmt.Errorf("data provided was in an unexpected format")
	}
}
