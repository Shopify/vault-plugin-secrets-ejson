package secretsejson

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/hashicorp/vault/sdk/logical"
)

func TestEJSON_Analyse(t *testing.T) {
	b, storage := getTestBackend(t)

	EJSON_Keys_Setup(t, b, storage)

	testDocumentJson := `{
		"_public_key": "15838c2f3260185ad2a8e1298bd507479ff2470b9e9c1fd89e0fdfefe2959f56",
		"asecret": "EJ[1:6+JkAgsjuL9q21HPH3RKpDcIUEfeDY+P+djp2iRfC2w=:Bu1EWAJUwWJfcc5S63oG4HaxJBc4AO6G:xU8uMuvX4CPBOI7aIdpw/+dB2A64doM6vN6Y]",
		"_bsecret": "orly",
		"anumber": 1,
		"production_signing_key": "EJ[1:6+JkAgsjuL9q21HPH3RKpDcIUEfeDY+P+djp2iRfC2w=:Dpqlq3+j7/Y80aFhOFN9MZeCu635EIrZ:LvLdA8VY+EePsdjoB7VUNe7jNIVJvz1/xuqH8z73MXEYzjCJTru6u08law01CBfTj+tJ3D0nr3Eo5qO5YlyNiTekgfWPFKztQakLHtoWR7qQicXS2us70nP4jij7dlV/K33B+f/rQs8OkeU2]",
		"github": "EJ[1:6+JkAgsjuL9q21HPH3RKpDcIUEfeDY+P+djp2iRfC2w=:+mx+EZTrHdnLxCVWEtvjqCfYn6JXe908:h48el99MUn7ukFWIeFruk2jHRMHCN1xZXmDGzcgZac+/CggF68krFdyBhL9NMJbm3OZajeBxqI4=]",
		"backend_system": "EJ[1:6+JkAgsjuL9q21HPH3RKpDcIUEfeDY+P+djp2iRfC2w=:eopckJmGcZRUbCyuZ/kBLGdyf/1qap3x:SVU/DcH2eSS0//pQIerjw8R+XtySZXtSjlV1QB0aVpbMzb65H8obSB3tTVvHVsBSp02NmPjUQn9jgAaKAkZu60ArLoAkmYY=]",
		"database": {
			"_username": "admin",
			"password": "EJ[1:6+JkAgsjuL9q21HPH3RKpDcIUEfeDY+P+djp2iRfC2w=:1LlOBYFfDBDlm1GgyN+kIcKgOUfCB24c:qWqQhU4pOnSVJRo4hxaqAINVoRC88A==]"
		}
	}`

	dataInput := map[string]interface{}{}
	if err := json.Unmarshal([]byte(testDocumentJson), &dataInput); err != nil {
		t.Fatalf("Could not load test data")
	}

	req := &logical.Request{
		Operation: logical.CreateOperation,
		Path:      "analysis",
		Storage:   storage,
		Data:      dataInput,
	}

	resp, err := b.HandleRequest(context.Background(), req)
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("err:%s resp:%#v\n", err, resp)
	}

}
