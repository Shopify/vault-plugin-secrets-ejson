package secretsejson

import (
	"context"
	"reflect"
	"testing"

	"github.com/hashicorp/vault/logical"
)

func TestEJSON_Data_Put(t *testing.T) {
	b, storage := getTestBackend(t)

	EJSON_Keys_Setup(t, b, storage)

	data := map[string]interface{}{
		"ejson": map[string]interface{}{
			"_public_key": "15838c2f3260185ad2a8e1298bd507479ff2470b9e9c1fd89e0fdfefe2959f56",
			"asecret":     "EJ[1:sdseJpJ3BpP9PO5Qs8IB4urmmYil46edSTek8SjgVGA=:zl7mkBzL4g2d0PE3hPucmfbDjf3aDK7K:iryi3H7wRGWvUI8kjfWLtP3sFiw=]",
			"anumber":     1,
		},
	}

	req := &logical.Request{
		Operation: logical.CreateOperation,
		Path:      "itsasecret",
		Storage:   storage,
		Data:      data,
	}

	resp, err := b.HandleRequest(context.Background(), req)
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("err:%s resp:%#v\n", err, resp)
	}
}

func TestEJSON_Data_Get(t *testing.T) {
	b, storage := getTestBackend(t)

	EJSON_Keys_Setup(t, b, storage)

	dataInput := map[string]interface{}{
		"ejson": map[string]interface{}{
			"_public_key": "15838c2f3260185ad2a8e1298bd507479ff2470b9e9c1fd89e0fdfefe2959f56",
			"asecret":     "EJ[1:sdseJpJ3BpP9PO5Qs8IB4urmmYil46edSTek8SjgVGA=:zl7mkBzL4g2d0PE3hPucmfbDjf3aDK7K:iryi3H7wRGWvUI8kjfWLtP3sFiw=]",
			"anumber":     float64(1),
		},
	}

	reqWrite := &logical.Request{
		Operation: logical.CreateOperation,
		Path:      "itsasecret",
		Storage:   storage,
		Data:      dataInput,
	}

	respWrite, err := b.HandleRequest(context.Background(), reqWrite)
	if err != nil || (respWrite != nil && respWrite.IsError()) {
		t.Fatalf("err:%s resp:%#v\n", err, respWrite)
	}

	reqReadEnc := &logical.Request{
		Operation: logical.ReadOperation,
		Path:      "itsasecret",
		Storage:   storage,
	}

	respReadEnc, err := b.HandleRequest(context.Background(), reqReadEnc)
	if err != nil || (respReadEnc != nil && respReadEnc.IsError()) {
		t.Fatalf("err:%s resp:%#v\n", err, respReadEnc)
	}

	if !reflect.DeepEqual(respReadEnc.Data["ejson"], dataInput["ejson"]) {
		t.Fatalf("Bad encryption response: \nGot: %#v\nWant: %#v", respReadEnc.Data["ejson"], dataInput["ejson"])
	}

	reqReadDec := &logical.Request{
		Operation: logical.ReadOperation,
		Path:      "itsasecret/decrypted",
		Storage:   storage,
	}

	respReadDec, err := b.HandleRequest(context.Background(), reqReadDec)
	if err != nil || (respReadDec != nil && respReadDec.IsError()) {
		t.Fatalf("err:%s resp:%#v\n", err, respReadDec)
	}

	dataDec := map[string]interface{}{
		"ejson": map[string]interface{}{
			"asecret": "ohai",
			"anumber": float64(1),
		},
	}

	if !reflect.DeepEqual(respReadDec.Data["ejson"], dataDec["ejson"]) {
		t.Fatalf("Bad decryption response: \nGot: %#v\nWant: %#v", respReadDec.Data["ejson"], dataDec["ejson"])
	}
}

func TestEJSON_Data_Delete(t *testing.T) {
	b, storage := getTestBackend(t)

	EJSON_Keys_Setup(t, b, storage)

	dataInput := map[string]interface{}{
		"ejson": map[string]interface{}{
			"_public_key": "15838c2f3260185ad2a8e1298bd507479ff2470b9e9c1fd89e0fdfefe2959f56",
			"asecret":     "EJ[1:sdseJpJ3BpP9PO5Qs8IB4urmmYil46edSTek8SjgVGA=:zl7mkBzL4g2d0PE3hPucmfbDjf3aDK7K:iryi3H7wRGWvUI8kjfWLtP3sFiw=]",
			"anumber":     float64(1),
		},
	}

	reqWrite := &logical.Request{
		Operation: logical.CreateOperation,
		Path:      "itsasecret",
		Storage:   storage,
		Data:      dataInput,
	}

	respWrite, err := b.HandleRequest(context.Background(), reqWrite)
	if err != nil || (respWrite != nil && respWrite.IsError()) {
		t.Fatalf("err:%s resp:%#v\n", err, respWrite)
	}
	reqDelete := &logical.Request{
		Operation: logical.DeleteOperation,
		Path:      "itsasecret",
		Storage:   storage,
	}

	respDelete, err := b.HandleRequest(context.Background(), reqDelete)
	if err != nil || (respDelete != nil && respDelete.IsError()) {
		t.Fatalf("err:%s resp:%#v\n", err, respDelete)
	}

	reqReadEnc := &logical.Request{
		Operation: logical.ReadOperation,
		Path:      "itsasecret",
		Storage:   storage,
	}

	respReadEnc, err := b.HandleRequest(context.Background(), reqReadEnc)
	if err != nil || (respReadEnc != nil && respReadEnc.IsError()) {
		t.Fatalf("err:%s resp:%#v\n", err, respReadEnc)
	}

	if respReadEnc != nil {
		t.Fatalf("Read encrypted data that was supposed to be deleted: \n%#v", respReadEnc)
	}

	reqReadDec := &logical.Request{
		Operation: logical.ReadOperation,
		Path:      "itsasecret/decrypted",
		Storage:   storage,
	}

	respReadDec, err := b.HandleRequest(context.Background(), reqReadDec)
	if err != nil || (respReadDec != nil && respReadDec.IsError()) {
		t.Fatalf("err:%s resp:%#v\n", err, respReadDec)
	}

	if respReadDec != nil {
		t.Fatalf("Read decrypted data that was supposed to be deleted: \n%#v", respReadDec)
	}
}

func TestEJSON_Data_List(t *testing.T) {
	b, storage := getTestBackend(t)

	EJSON_Keys_Setup(t, b, storage)

	dataInput := map[string]interface{}{
		"ejson": map[string]interface{}{
			"_public_key": "15838c2f3260185ad2a8e1298bd507479ff2470b9e9c1fd89e0fdfefe2959f56",
			"asecret":     "EJ[1:sdseJpJ3BpP9PO5Qs8IB4urmmYil46edSTek8SjgVGA=:zl7mkBzL4g2d0PE3hPucmfbDjf3aDK7K:iryi3H7wRGWvUI8kjfWLtP3sFiw=]",
			"anumber":     float64(1),
		},
	}

	reqWrite := &logical.Request{
		Operation: logical.CreateOperation,
		Path:      "itsasecret",
		Storage:   storage,
		Data:      dataInput,
	}

	respWrite, err := b.HandleRequest(context.Background(), reqWrite)
	if err != nil || (respWrite != nil && respWrite.IsError()) {
		t.Fatalf("err:%s resp:%#v\n", err, respWrite)
	}

	reqList := &logical.Request{
		Operation: logical.ListOperation,
		Path:      "",
		Storage:   storage,
	}

	respList, err := b.HandleRequest(context.Background(), reqList)
	if err != nil || (respList != nil && respList.IsError()) {
		t.Fatalf("err:%s resp:%#v\n", err, respList)
	}

	dataList := []string{
		"itsasecret",
		"itsasecret/",
		"keys/",
	}

	if !reflect.DeepEqual(respList.Data["keys"], dataList) {
		t.Fatalf("Bad list response: \nGot: %#v\nWant: %#v", respList.Data["keys"], dataList)
	}
}
