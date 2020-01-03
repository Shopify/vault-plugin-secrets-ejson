package secretsejson

import (
	"context"
	"reflect"
	"testing"

	"github.com/hashicorp/vault/sdk/logical"
)

func EJSON_Keys_Setup(t *testing.T, b logical.Backend, storage logical.Storage) {
	dataInput := map[string]interface{}{
		"public":  "15838c2f3260185ad2a8e1298bd507479ff2470b9e9c1fd89e0fdfefe2959f56",
		"private": "37124bcf00c2d9fd87ddd596162d99c004460fd47130f2d653e45f85a0681cf0",
	}

	reqKP := &logical.Request{
		Operation: logical.CreateOperation,
		Path:      "keys/15838c2f3260185ad2a8e1298bd507479ff2470b9e9c1fd89e0fdfefe2959f56",
		Storage:   storage,
		Data:      dataInput,
	}

	respKP, err := b.HandleRequest(context.Background(), reqKP)
	if err != nil || (respKP != nil && respKP.IsError()) {
		t.Fatalf("err:%s resp:%#v\n", err, respKP)
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

	reqList := &logical.Request{
		Operation: logical.ListOperation,
		Path:      "keys/",
		Storage:   storage,
	}

	respList, err := b.HandleRequest(context.Background(), reqList)
	if err != nil || (respList != nil && respList.IsError()) {
		t.Fatalf("err:%s resp:%#v\n", err, respList)
	}

	dataList := []string{
		"15838c2f3260185ad2a8e1298bd507479ff2470b9e9c1fd89e0fdfefe2959f56",
	}

	if !reflect.DeepEqual(respList.Data["keys"], dataList) {
		t.Fatalf("Bad list response: \nGot: %#v\nWant: %#v", respList.Data["keys"], dataList)
	}
}
