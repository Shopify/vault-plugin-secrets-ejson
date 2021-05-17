# Vault Plugin: EJSON Secrets Backend

[![Build Status](https://travis-ci.com/Shopify/vault-plugin-secrets-ejson.svg?branch=master)](https://travis-ci.com/Shopify/vault-plugin-secrets-ejson)

## Summary

A secret plugin for use with [Hashicorp Vault](https://www.github.com/hashicorp/vault). This plugin provides the ability to submit and manipulate [EJSON](https://github.com/Shopify/ejson) to Vault wherein it can be decrypted and/or stored.

Note: For storage operations, any key values prefixed with an underscore will be stored with the underscore removed at the decrypted path (see below for an example). This is done intentionally to keep data access sane.

## Usage

### Installing for development use

```bash
# Build the binary
$ make build

# Run Vault
# NOTE: Do not run -dev in production
$ vault server -dev -dev-root-token-id=root -dev-plugin-dir=./vault/plugins

# Export VAULT_ADDR for future `vault` commands
$ export VAULT_ADDR='http://127.0.0.1:8200'

# Enable the plugin at a specific path (in this case ejson/)
$ vault secrets enable -path=ejson secrets-ejson
Success! Enabled the vault-plugin-secrets-ejson plugin at: ejson/
```

### Installing for production use
Please consult official Vault documentation on how to checksum, load and enable plugins.

## Demo


### Generating public-private-keypairs (/keypair)

```bash
$ vault write -force ejson/keypair
Key       Value
---       -----
public    7f0510f044e9ae852f8ae2865cce55ae01f3b9c0f505b1b33b6323579b778a30

$ vault list ejson/keys
Keys
----
7f0510f044e9ae852f8ae2865cce55ae01f3b9c0f505b1b33b6323579b778a30

$ vault read ejson/keys/7f0510f044e9ae852f8ae2865cce55ae01f3b9c0f505b1b33b6323579b778a30
Key        Value
---        -----
private    1430dc364475c63e21cc549ad74245970bfa70b98b9497e7f3c71dd3ce7cb13c
```

### Storing public-private-keypairs (/keys/.*)

```bash
# Storing the public/private key for decryption
# This needs to be done first, and the secret must be underneath keys/
$ vault write ejson/keys/15838c2f3260185ad2a8e1298bd507479ff2470b9e9c1fd89e0fdfefe2959f56 private="37124bcf00c2d9fd87ddd596162d99c004460fd47130f2d653e45f85a0681cf0"
Key        Value
---        -----
private    37124bcf00c2d9fd87ddd596162d99c004460fd47130f2d653e45f85a0681cf0
```

### Storing ejson documents (/.*)
```bash
$ cat itsasecret.ejson
{
  "_public_key": "15838c2f3260185ad2a8e1298bd507479ff2470b9e9c1fd89e0fdfefe2959f56",
  "asecret": "EJ[1:sdseJpJ3BpP9PO5Qs8IB4urmmYil46edSTek8SjgVGA=:zl7mkBzL4g2d0PE3hPucmfbDjf3aDK7K:iryi3H7wRGWvUI8kjfWLtP3sFiw=]",
  "_bsecret": "orly",
  "anumber": 1
}

$ vault write ejson/itsasecret @itsasecret.ejson
Key      Value
---      -----
ejson    map[_bsecret:orly _public_key:15838c2f3260185ad2a8e1298bd507479ff2470b9e9c1fd89e0fdfefe2959f56 anumber:1 asecret:EJ[1:sdseJpJ3BpP9PO5Qs8IB4urmmYil46edSTek8SjgVGA=:zl7mkBzL4g2d0PE3hPucmfbDjf3aDK7K:iryi3H7wRGWvUI8kjfWLtP3sFiw=]]

# Encrypted payload, useful for safely comparing values with other tools (e.g. Terraform)
$ vault read ejson/itsasecret
Key      Value
---      -----
ejson    map[_bsecret:orly _public_key:15838c2f3260185ad2a8e1298bd507479ff2470b9e9c1fd89e0fdfefe2959f56 anumber:1 asecret:EJ[1:sdseJpJ3BpP9PO5Qs8IB4urmmYil46edSTek8SjgVGA=:zl7mkBzL4g2d0PE3hPucmfbDjf3aDK7K:iryi3H7wRGWvUI8kjfWLtP3sFiw=]]

# Decrypted payload, useful for consumption!
$ vault read ejson/itsasecret/decrypted
Key      Value
---      -----
ejson    map[anumber:1 asecret:ohai bsecret:orly]
```

### Decrypting an ejson document on the fly with EaaS (/decrypt)
```bash
$ vault write -format=json ejson/decrypt @itsasecret.ejson
{
  "request_id": "3df23dd2-7c41-3c3f-b5e4-d5300906bd78",
  "lease_id": "",
  "lease_duration": 0,
  "renewable": false,
  "data": {
    "_bsecret": "orly",
    "_public_key": "15838c2f3260185ad2a8e1298bd507479ff2470b9e9c1fd89e0fdfefe2959f56",
    "anumber": 1,
    "asecret": "to everyone",
    "database": {
      "_username": "admin",
      "password": "sicher"
    }
  },
  "warnings": null
}
```

### Uniquely identify a plain text secret (/identity)
To help with identifying secrets across multiple ejson documents, this EaaS function can be used to generate a unique string for any given plain text.
```bash
# This needs to be done first, and the secret salt must be underneath keys/
# If not set however, a default value will be used. This is considered less secure, especially if applied
# to low entropy plain text.
$ vault write ejson/keys/__secret_salt private="SOME_LONG_AND_RANDOM_STRING_THAT_SHOULD_BE_KEPT_SECRET"
Key        Value
---        -----
private    SOME_LONG_AND_RANDOM_STRING_THAT_SHOULD_BE_KEPT_SECRET

$ vault write ejson/identity plaintext="p4ssw0rd"
Key         Value
---         -----
identity    1ab30335c71ede6e08ef18f6ee68ad2e893edd3eb12a5629b899be9149777ee1
```


### Terraform integration

This plugin can also be used with Terraform's `vault_generic_secret` resource to safely store version controlled secrets inside of Vault.

```bash
$ cat main.tf
provider "vault" {}

resource "vault_generic_secret" "example" {
  path = "ejson/itsasecret"

  data_json = <<EOT
{
  "ejson": {
    "_public_key": "15838c2f3260185ad2a8e1298bd507479ff2470b9e9c1fd89e0fdfefe2959f56",
    "asecret": "EJ[1:sdseJpJ3BpP9PO5Qs8IB4urmmYil46edSTek8SjgVGA=:zl7mkBzL4g2d0PE3hPucmfbDjf3aDK7K:iryi3H7wRGWvUI8kjfWLtP3sFiw=]",
    "_bsecret": "orly",
    "anumber": 1
  }
}
EOT
}

# Initial apply
$ terraform apply -auto-approve
vault_generic_secret.example: Refreshing state... (ID: ejson/itsasecret)
vault_generic_secret.example: Creating...
  data_json:    "" => "{\"ejson\":{\"_public_key\":\"15838c2f3260185ad2a8e1298bd507479ff2470b9e9c1fd89e0fdfefe2959f56\",\"anumber\":1,\"asecret\":\"EJ[1:dPD6H7zfvJRwpJEIixW4HmZOSr+Mwi68Dtp0h+w5fAM=:lsAK/idjgbFagIWHIooBmVsTwFO1xr/1:cyzQwFGgAnMH24wVTwQKpSAw0V2vFQsD7x329g==]\",\"_bsecret\":\"orly\",\"anumber\":\"1\"}}"
  disable_read: "" => "false"
  path:         "" => "ejson/itsasecret"
vault_generic_secret.example: Creation complete after 0s (ID: ejson/itsasecret)

Apply complete! Resources: 1 added, 0 changed, 0 destroyed.

# Re-apply
# NOTE: This will never print out the decrypted secrets as it only compares the encrypted payload
$ terraform apply -auto-approve
vault_generic_secret.example: Refreshing state... (ID: ejson/itsasecret)

Apply complete! Resources: 0 added, 0 changed, 0 destroyed
```

## Contributing

See [CONTRIBUTING](./CONTRIBUTING.md).

## License

See [LICENSE](./LICENSE)
