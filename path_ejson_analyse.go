package secretsejson

import (
	"context"
	"encoding/json"
	"fmt"
	"regexp"
	"strings"

	ej "github.com/Shopify/ejson/json"
	"github.com/hashicorp/errwrap"
	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

func typeRegexes() map[string]string {

	// Adapted from https://github.com/dxa4481/truffleHogRegexes/blob/master/truffleHogRegexes/regexes.json
	// Regexp list is GNU General Public License v3.0, see https://github.com/dxa4481/truffleHogRegexes/blob/master/LICENSE
	truffehogRegexesJson := `{
		"Slack Token": "(xox[pboa]-[0-9]{12}-[0-9]{12}-[0-9]{12}-[a-z0-9]{32})",
		"RSA private key": "-----BEGIN RSA PRIVATE KEY-----",
		"SSH (DSA) private key": "-----BEGIN DSA PRIVATE KEY-----",
		"SSH (EC) private key": "-----BEGIN EC PRIVATE KEY-----",
		"PGP private key block": "-----BEGIN PGP PRIVATE KEY BLOCK-----",
		"AWS API Key": "((?:A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16})",
		"Amazon MWS Auth Token": "amzn\\.mws\\.[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}",
		"AWS API Key": "AKIA[0-9A-Z]{16}",
		"AWS AppSync GraphQL Key": "da2-[a-z0-9]{26}",
		"Facebook Access Token": "EAACEdEose0cBA[0-9A-Za-z]+",
		"Facebook OAuth": "[fF][aA][cC][eE][bB][oO][oO][kK].*['|\"][0-9a-f]{32}['|\"]",
		"GitHub": "[gG][iI][tT][hH][uU][bB].*['|\"][0-9a-zA-Z]{35,40}['|\"]",
		"GitHub PAT": "ghp_[0-9a-zA-Z]{35,40}",
		"Generic API Key": "[aA][pP][iI]_?[kK][eE][yY].*['|\"][0-9a-zA-Z]{32,45}['|\"]",
		"Generic Secret": "[sS][eE][cC][rR][eE][tT].*['|\"][0-9a-zA-Z]{32,45}['|\"]",
		"Google API Key": "AIza[0-9A-Za-z\\-_]{35}",
		"Google Cloud Platform API Key": "AIza[0-9A-Za-z\\-_]{35}",
		"Google Cloud Platform OAuth": "[0-9]+-[0-9A-Za-z_]{32}\\.apps\\.googleusercontent\\.com",
		"Google Drive API Key": "AIza[0-9A-Za-z\\-_]{35}",
		"Google Drive OAuth": "[0-9]+-[0-9A-Za-z_]{32}\\.apps\\.googleusercontent\\.com",
		"Google (GCP) Service-account": "\"type\": \"service_account\"",
		"Google Gmail API Key": "AIza[0-9A-Za-z\\-_]{35}",
		"Google Gmail OAuth": "[0-9]+-[0-9A-Za-z_]{32}\\.apps\\.googleusercontent\\.com",
		"Google OAuth Access Token": "ya29\\.[0-9A-Za-z\\-_]+",
		"Google YouTube API Key": "AIza[0-9A-Za-z\\-_]{35}",
		"Google YouTube OAuth": "[0-9]+-[0-9A-Za-z_]{32}\\.apps\\.googleusercontent\\.com",
		"Heroku API Key": "[hH][eE][rR][oO][kK][uU].*[0-9A-F]{8}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{12}",
		"MailChimp API Key": "[0-9a-f]{32}-us[0-9]{1,2}",
		"Mailgun API Key": "key-[0-9a-zA-Z]{32}",
		"URL": "[a-zA-Z]{3,10}://.+",
		"PayPal Braintree Access Token": "access_token\\$production\\$[0-9a-z]{16}\\$[0-9a-f]{32}",
		"Picatic API Key": "sk_live_[0-9a-z]{32}",
		"Slack Webhook": "https://hooks\\.slack\\.com/services/T[a-zA-Z0-9_]{8}/B[a-zA-Z0-9_]{8}/[a-zA-Z0-9_]{24}",
		"Stripe API Key": "sk_live_[0-9a-zA-Z]{24}",
		"Stripe Restricted API Key": "rk_live_[0-9a-zA-Z]{24}",
		"Square Access Token": "sq0atp-[0-9A-Za-z\\-_]{22}",
		"Square OAuth Secret": "sq0csp-[0-9A-Za-z\\-_]{43}",
		"Telegram Bot API Key": "[0-9]+:AA[0-9A-Za-z\\-_]{33}",
		"Twilio API Key": "SK[0-9a-fA-F]{32}",
		"Twitter Access Token": "[tT][wW][iI][tT][tT][eE][rR].*[1-9][0-9]+-[0-9a-zA-Z]{40}",
		"Twitter OAuth": "[tT][wW][iI][tT][tT][eE][rR].*['|\"][0-9a-zA-Z]{35,44}['|\"]"
	}`

	truffehogRegexes := map[string]string{}
	if err := json.Unmarshal([]byte(truffehogRegexesJson), &truffehogRegexes); err != nil {
		return nil
	}
	return truffehogRegexes
}

func ejsonAnalysePaths(b *backend) []*framework.Path {
	return []*framework.Path{
		&framework.Path{
			Pattern: "analyse",
			Fields: map[string]*framework.FieldSchema{
				"document": &framework.FieldSchema{
					Type:        framework.TypeString,
					Description: "ejson document",
				},
			},
			Callbacks: map[logical.Operation]framework.OperationFunc{
				logical.CreateOperation: b.analyse,
				logical.UpdateOperation: b.analyse,
			},
		},
	}
}

func (b *backend) analyse(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	inputData, ok := data.GetOk("document")
	if !ok {
		if len(data.Raw) == 0 {
			return logical.ErrorResponse("no data provided"), logical.ErrInvalidRequest
		}
		inputData = data.Raw
	}

	encData, err := MarshalInput(inputData)
	if err != nil {
		return nil, errwrap.Wrapf("failed to marshall json: {{err}}", err)
	}

	decData, err := DecryptEjson(ctx, encData, req.Storage)
	if err != nil {
		return nil, errwrap.Wrapf("failed to decrypt ejson: {{err}}", err)
	}

	walker := ej.Walker{
		Action: analyser(identityFunction(b.IdentitySaltOrDefault(ctx, req))),
	}

	analysedData, err := walker.Walk(decData)
	if err != nil {
		return nil, errwrap.Wrapf("failed to analyse ejson: {{err}}", err)
	}
	analysedJson := map[string]interface{}{}
	if err := json.Unmarshal(analysedData, &analysedJson); err != nil {
		return nil, err
	}

	return &logical.Response{
		Data: analysedJson,
	}, nil
}

func identityFunction(salt []byte) func([]byte) ([]byte, error) {
	return func(value []byte) ([]byte, error) {
		return HashPlaintext(value, salt)
	}
}

func analyser(identityFunction func([]byte) ([]byte, error)) func(value []byte) ([]byte, error) {
	return func(value []byte) ([]byte, error) {
		identity, err := identityFunction(value)
		if err != nil {
			return nil, err
		}

		result := fmt.Sprintf(
			"EJA[1:%x:%s:%s]",
			identity,
			secretType(value),
			strings.Join(secretWarnings(value), ","),
		)
		return []byte(result), nil
	}
}

func secretWarnings(secret []byte) []string {
	res := []string{}
	if len(secret) <= 10 {
		res = append(res, "VERY_SHORT")
	}
	if len(secret) > 10 && len(secret) <= 16 {
		res = append(res, "SHORT")
	}
	return res
}

func secretType(secret []byte) string {
	for secretType, secretRegexp := range typeRegexes() {
		if matched, _ := regexp.MatchString(secretRegexp, string(secret)); matched {
			return secretType
		}
	}
	return "GENERIC_PASSWORD"
}
