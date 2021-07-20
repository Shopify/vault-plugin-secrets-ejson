package secretsejson

import (
	"context"
	"fmt"
	"reflect"
	"testing"

	"github.com/hashicorp/vault/sdk/logical"
)

func EJSON_Keys_Setup(t *testing.T, b logical.Backend, storage logical.Storage) {
	dataInputs := []map[string]interface{}{
		{
			"public":  "15838c2f3260185ad2a8e1298bd507479ff2470b9e9c1fd89e0fdfefe2959f56",
			"private": "37124bcf00c2d9fd87ddd596162d99c004460fd47130f2d653e45f85a0681cf0",
		},
		{
			"public":  "65f9592efefdf0e98df1c9e9b0742ff974705db8921e8a2da5810623f2c83851",
			"private": "0fc1860a58f54e356d2f03174df064400c99d261695ddd78df9d2c00fcb42173",
		},
	}

	for _, dataInput := range dataInputs {
		reqKP := &logical.Request{
			Operation: logical.CreateOperation,
			Path:      fmt.Sprintf("keys/%s", dataInput["public"]),
			Storage:   storage,
			Data:      dataInput,
		}

		respKP, err := b.HandleRequest(context.Background(), reqKP)
		if err != nil || (respKP != nil && respKP.IsError()) {
			t.Fatalf("err:%s resp:%#v\n", err, respKP)
		}
	}
}

func TestEJSON_Keys_Data_Put(t *testing.T) {
	b, storage := getTestBackend(t)

	EJSON_Keys_Setup(t, b, storage)
}

func TestEJSON_Keys_Data_Get(t *testing.T) {
	b, storage := getTestBackend(t)

	EJSON_Keys_Setup(t, b, storage)

	dataInput := map[string]interface{}{
		"public":  "15838c2f3260185ad2a8e1298bd507479ff2470b9e9c1fd89e0fdfefe2959f56",
		"private": "37124bcf00c2d9fd87ddd596162d99c004460fd47130f2d653e45f85a0681cf0",
	}

	reqRead := &logical.Request{
		Operation: logical.ReadOperation,
		Path:      "keys/15838c2f3260185ad2a8e1298bd507479ff2470b9e9c1fd89e0fdfefe2959f56",
		Storage:   storage,
	}

	respRead, err := b.HandleRequest(context.Background(), reqRead)
	if err != nil || (respRead != nil && respRead.IsError()) {
		t.Fatalf("err:%s resp:%#v\n", err, respRead)
	}

	if !reflect.DeepEqual(respRead.Data["private"], dataInput["private"]) {
		t.Fatalf("Bad encryption response: \nGot: %#v\nWant: %#v", respRead.Data["private"], dataInput["private"])
	}
}

func TestEJSON_Keys_Data_Delete(t *testing.T) {
	b, storage := getTestBackend(t)

	EJSON_Keys_Setup(t, b, storage)

	reqDelete := &logical.Request{
		Operation: logical.DeleteOperation,
		Path:      "itsasecret",
		Storage:   storage,
	}

	respDelete, err := b.HandleRequest(context.Background(), reqDelete)
	if err != nil || (respDelete != nil && respDelete.IsError()) {
		t.Fatalf("err:%s resp:%#v\n", err, respDelete)
	}
}

func TestEJSON_Keys_Data_List(t *testing.T) {
	b, storage := getTestBackend(t)

	EJSON_Keys_Setup(t, b, storage)

	respList, err := listKeys(b, storage)
	if err != nil {
		t.Fatalf("Could not list keys: %#v", err)
	}

	dataList := []string{
		"15838c2f3260185ad2a8e1298bd507479ff2470b9e9c1fd89e0fdfefe2959f56",
		"65f9592efefdf0e98df1c9e9b0742ff974705db8921e8a2da5810623f2c83851",
	}

	if !reflect.DeepEqual(respList, dataList) {
		t.Fatalf("Bad list response: \nGot: %#v\nWant: %#v", respList, dataList)
	}
}

func listKeys(b logical.Backend, storage logical.Storage) ([]string, error) {
	reqList := &logical.Request{
		Operation: logical.ListOperation,
		Path:      "keys/",
		Storage:   storage,
	}

	respList, err := b.HandleRequest(context.Background(), reqList)
	if err != nil || (respList != nil && respList.IsError()) {
		return nil, err
	}
	keys := respList.Data["keys"].([]string)

	return keys, nil
}

func TestEJSON_KeyPairCreate(t *testing.T) {
	b, storage := getTestBackend(t)

	EJSON_Keys_Setup(t, b, storage)

	keys, err := listKeys(b, storage)
	if err != nil {
		t.Fatalf("Could not list keys: %#v", err)
	}
	numberOfKeys := len(keys)

	reqList := &logical.Request{
		Operation: logical.CreateOperation,
		Path:      "keypair",
		Storage:   storage,
	}
	respList, err := b.HandleRequest(context.Background(), reqList)
	if err != nil || (respList != nil && respList.IsError()) {
		t.Fatalf("err:%s resp:%#v\n", err, respList)
	}

	keys, err = listKeys(b, storage)
	if err != nil {
		t.Fatalf("Could not list keys: %#v", err)
	}
	if len(keys) != (numberOfKeys + 1) {
		t.Fatalf("write /keypair Did not add one new key to keys/")
	}
}
