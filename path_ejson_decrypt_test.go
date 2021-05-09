package secretsejson

import (
	"context"
	"reflect"
	"testing"

	"github.com/hashicorp/vault/sdk/logical"
)

func TestEJSON_Decrypt(t *testing.T) {
	b, storage := getTestBackend(t)

	EJSON_Keys_Setup(t, b, storage)

	dataInput := map[string]interface{}{
		"_public_key": "15838c2f3260185ad2a8e1298bd507479ff2470b9e9c1fd89e0fdfefe2959f56",
		"asecret":     "EJ[1:sdseJpJ3BpP9PO5Qs8IB4urmmYil46edSTek8SjgVGA=:zl7mkBzL4g2d0PE3hPucmfbDjf3aDK7K:iryi3H7wRGWvUI8kjfWLtP3sFiw=]",
		"_bsecret":    "intentionally_left_unencrypted",
		"anumber":     1,
	}

	req := &logical.Request{
		Operation: logical.CreateOperation,
		Path:      "decrypt",
		Storage:   storage,
		Data:      dataInput,
	}

	resp, err := b.HandleRequest(context.Background(), req)
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("err:%s resp:%#v\n", err, resp)
	}

	dataDec := dataInput
	dataDec["asecret"] = "ohai"
	dataDec["anumber"] = float64(1) // deep equal is a little too picky on numbers here

	if !reflect.DeepEqual(resp.Data, dataDec) {
		t.Fatalf("Bad decryption response: \nGot: %#v\nWant: %#v", resp.Data, dataDec)
	}
}
