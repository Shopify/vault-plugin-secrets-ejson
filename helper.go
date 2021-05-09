package secretsejson

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"

	"github.com/Shopify/ejson"
	ej "github.com/Shopify/ejson/json"
	"github.com/hashicorp/vault/sdk/logical"
	"golang.org/x/crypto/scrypt"
)

func DecryptEjsonDocument(ctx context.Context, req *logical.Request, encData []byte) (map[string]interface{}, error) {

	decBytes, err := DecryptEjson(ctx, encData, req.Storage)
	if err != nil {
		return nil, err
	}
	decData := map[string]interface{}{}
	if err := json.Unmarshal(decBytes, &decData); err != nil {
		return nil, err
	}

	return decData, nil
}

func DecryptEjson(ctx context.Context, encData []byte, storage logical.Storage) ([]byte, error) {
	var out bytes.Buffer
	var err error

	pubKey, err := ej.ExtractPublicKey(encData)
	if err != nil {
		return nil, fmt.Errorf("failed to extract public key: %s", err)
	}

	// Find the matching public key in keys/
	keyPair, err := storage.Get(ctx, fmt.Sprintf("keys/%x", pubKey))
	if err != nil || keyPair == nil {
		return nil, fmt.Errorf("failed to find public key in keys/: %s", err)
	}

	if err := ejson.Decrypt(bytes.NewBuffer(encData), &out, "", string(keyPair.Value)); err != nil {
		return nil, fmt.Errorf("failed to decrypt ejson: %s", err)
	}
	return out.Bytes(), nil
}

func MarshalInput(inputData interface{}) ([]byte, error) {
	switch value := inputData.(type) {
	case map[string]interface{}:
		return MarshalForEjson(value)
	default:
		return nil, fmt.Errorf("data provided was in an unexpected format")
	}
}

func MarshalForEjson(input map[string]interface{}) ([]byte, error) {
	bytes, err := json.Marshal(input)
	if err != nil {
		return nil, err
	}
	return bytes, nil
}

func HashPlaintext(plaintext []byte, salt []byte) ([]byte, error) {
	return scrypt.Key(plaintext, salt, 1<<14, 8, 1, 32)
}

func (b *backend) IdentitySaltOrDefault(ctx context.Context, req *logical.Request) []byte {
	// IMPROVEMENT: find something that works idenpendent of keys/
	secretSalt, err := req.Storage.Get(ctx, "keys/__secret_salt")
	if err != nil || secretSalt == nil {
		b.Logger().Warn("No `secret_salt` set for ejson plaintext identity, using known insecure default!")
		return []byte("ejson")
	}
	return secretSalt.Value
}
