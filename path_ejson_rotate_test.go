package secretsejson

import (
	"context"
	"encoding/json"
	"reflect"
	"testing"

	ej "github.com/Shopify/ejson/json"
	"github.com/hashicorp/vault/sdk/logical"
)

func TestEJSON_Keys_Rotate_InlineDoc(t *testing.T) {
	b, storage := getTestBackend(t)
	EJSON_Keys_Setup(t, b, storage)

	publicKey := "15838c2f3260185ad2a8e1298bd507479ff2470b9e9c1fd89e0fdfefe2959f56"
	dataInput := map[string]interface{}{
		ej.PublicKeyField: publicKey,
		"asecret":         "EJ[1:sdseJpJ3BpP9PO5Qs8IB4urmmYil46edSTek8SjgVGA=:zl7mkBzL4g2d0PE3hPucmfbDjf3aDK7K:iryi3H7wRGWvUI8kjfWLtP3sFiw=]",
		"_bsecret":        "intentionally_left_unencrypted",
		"anumber":         1,
	}

	reqRotate := &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "rotate",
		Storage:   storage,
		Data:      dataInput,
	}

	respRead, err := b.HandleRequest(context.Background(), reqRotate)
	if err != nil || (respRead != nil && respRead.IsError()) {
		t.Fatalf("err:%s resp:%#v\n", err, respRead)
	}

	rotatedDoc, ok := respRead.Data["document"].(map[string]interface{})
	if !ok {
		t.Fatal("document missing from response", respRead)
	}

	if reflect.DeepEqual(rotatedDoc[ej.PublicKeyField], publicKey) {
		t.Fatalf("public keys did not change: \nPublicKey: %#v\n", rotatedDoc[ej.PublicKeyField])
	}

	publicKeys, err := storage.List(context.Background(), "keys/")
	if err != nil {
		t.Fatal(err)
	}

	if len(publicKeys) != 2 {
		t.Fatalf("keypairs for the rotated document missing from storage")
	}
}

func TestEJSON_Keys_Rotate_ExplicitDoc(t *testing.T) {
	b, storage := getTestBackend(t)
	EJSON_Keys_Setup(t, b, storage)

	publicKey := "15838c2f3260185ad2a8e1298bd507479ff2470b9e9c1fd89e0fdfefe2959f56"
	ejsonDoc := map[string]interface{}{
		ej.PublicKeyField: publicKey,
		"asecret":         "EJ[1:sdseJpJ3BpP9PO5Qs8IB4urmmYil46edSTek8SjgVGA=:zl7mkBzL4g2d0PE3hPucmfbDjf3aDK7K:iryi3H7wRGWvUI8kjfWLtP3sFiw=]",
		"_bsecret":        "intentionally_left_unencrypted",
		"anumber":         1,
	}

	ejsonDocBytes, err := json.Marshal(ejsonDoc)
	if err != nil {
		t.Fatal(err)
	}

	dataInput := map[string]interface{}{
		"document": string(ejsonDocBytes),
	}

	reqRotate := &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "rotate",
		Storage:   storage,
		Data:      dataInput,
	}

	respRead, err := b.HandleRequest(context.Background(), reqRotate)
	if err != nil || (respRead != nil && respRead.IsError()) {
		t.Fatalf("err:%s resp:%#v\n", err, respRead)
	}

	rotatedDoc, ok := respRead.Data["document"].(map[string]interface{})
	if !ok {
		t.Fatal("document missing from response", respRead)
	}

	if reflect.DeepEqual(rotatedDoc[ej.PublicKeyField], publicKey) {
		t.Fatalf("public keys did not change: \nPublicKey: %#v\n", rotatedDoc[ej.PublicKeyField])
	}

	publicKeys, err := storage.List(context.Background(), "keys/")
	if err != nil {
		t.Fatal(err)
	}

	if len(publicKeys) != 2 {
		t.Fatalf("keypairs for the rotated document missing from storage")
	}
}
