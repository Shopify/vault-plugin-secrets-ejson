package secretsejson

import (
	"context"
	"encoding/json"
	"reflect"
	"testing"

	ej "github.com/Shopify/ejson/json"
	"github.com/hashicorp/vault/sdk/logical"
)

func TestEJSON_Keys_Copy(t *testing.T) {
	b, storage := getTestBackend(t)
	EJSON_Keys_Setup(t, b, storage)

	ejsonDoc := map[string]interface{}{
		ej.PublicKeyField: "15838c2f3260185ad2a8e1298bd507479ff2470b9e9c1fd89e0fdfefe2959f56",
		"asecret":         "EJ[1:sdseJpJ3BpP9PO5Qs8IB4urmmYil46edSTek8SjgVGA=:zl7mkBzL4g2d0PE3hPucmfbDjf3aDK7K:iryi3H7wRGWvUI8kjfWLtP3sFiw=]",
		"_bsecret":        "intentionally_left_unencrypted",
		"anumber":         1,
	}
	ejsonDocBytes, err := json.Marshal(ejsonDoc)
	if err != nil {
		t.Fatal(err)
	}

	publicKey := "65f9592efefdf0e98df1c9e9b0742ff974705db8921e8a2da5810623f2c83851"

	dataInput := map[string]interface{}{
		"document":   string(ejsonDocBytes),
		"public_key": publicKey,
	}

	reqCopy := &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "copy",
		Storage:   storage,
		Data:      dataInput,
	}

	respRead, err := b.HandleRequest(context.Background(), reqCopy)
	if err != nil || (respRead != nil && respRead.IsError()) {
		t.Fatalf("err:%s resp:%#v\n", err, respRead)
	}

	copiedDoc, ok := respRead.Data["document"].(map[string]interface{})
	if !ok {
		t.Fatal("document missing from response", respRead)
	}

	if !reflect.DeepEqual(copiedDoc[ej.PublicKeyField], publicKey) {
		t.Fatalf("public key does not match provided public key:\n Got:      %#v\n Expected: %#v\n", copiedDoc[ej.PublicKeyField], publicKey)
	}
}
