package secretsejson

import (
	"context"
	"crypto/rand"
	"fmt"
	"testing"

	"github.com/hashicorp/vault/sdk/logical"
)

func TestEJSON_Identity_default(t *testing.T) {
	b, storage := getTestBackend(t)

	dataInput := map[string]interface{}{
		"plaintext": "a",
	}

	req := &logical.Request{
		Operation: logical.CreateOperation,
		Path:      "identity",
		Storage:   storage,
		Data:      dataInput,
	}
	resp, err := b.HandleRequest(context.Background(), req)
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("err:%s resp:%#v\n", err, resp)
	}

	expected := "fcc648ebfb10143d55ccf1a80eb40071f94e86f4650b51d4c52cf26eba6474cc"
	if resp.Data["identity"] != expected {
		t.Fatalf("Bad identity string with default salt: \nGot: %#v\nWant: %#v", resp.Data["identity"], expected)
	}
}

func TestEJSON_Identity_non_default(t *testing.T) {
	b, storage := getTestBackend(t)

	randomSalt := make([]byte, 32)
	_, err := rand.Read(randomSalt)
	if err != nil {
		t.Fatalf("test failed due to rand.Read eror: %s", err)
	}

	// First set `__secret_salt`
	dataInput := map[string]interface{}{
		"private": fmt.Sprintf("%x", randomSalt),
	}
	req := &logical.Request{
		Operation: logical.CreateOperation,
		Path:      "keys/__secret_salt",
		Storage:   storage,
		Data:      dataInput,
	}
	resp, err := b.HandleRequest(context.Background(), req)
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("err:%s resp:%#v\n", err, resp)
	}

	// Then generate identity string with salt set
	dataInput = map[string]interface{}{
		"plaintext": "a",
	}

	req = &logical.Request{
		Operation: logical.CreateOperation,
		Path:      "identity",
		Storage:   storage,
		Data:      dataInput,
	}
	resp, err = b.HandleRequest(context.Background(), req)
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("err:%s resp:%#v\n", err, resp)
	}

	expected := "fcc648ebfb10143d55ccf1a80eb40071f94e86f4650b51d4c52cf26eba6474cc"
	if resp.Data["identity"] == expected {
		t.Fatalf("Bad identity string with set salt: \nGot: %#v\nDid not want: %#v", resp.Data["identity"], expected)
	}
}
