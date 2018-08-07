# Vault Plugin: EJSON Secrets Backend

## Summary

A standalone backend plugin for use with [Hashicorp Vault](https://www.github.com/hashicorp/vault). This plugin provides the ability to submit [EJSON](https://github.com/Shopify/ejson) to Vault wherein it will be decrypted and stored.

## Usage

### Installing

```bash
# Generate a Vault config detailing where the plugin directory is located
$ tee vault-config.hcl <<EOF
plugin_directory = "/path/to/binary"
EOF

# Run Vault
# NOTE: Do not run -dev in production
$ vault server -dev -dev-root-token-id="root" -config=tmp/vault-config.hcl

# Export VAULT_ADDR for future `vault` commands
$ export VAULT_ADDR='http://127.0.0.1:8200'

# Build the binary
$ make build

# Generate checksum, and tell Vault about the plugin
$ SHASUM=$(shasum -a 256 "/path/to/binary/vault-plugin-secrets-ejson" | cut -d " " -f1)
$ vault write sys/plugins/catalog/vault-plugin-secrets-ejson \
  sha_256="$SHASUM" \
  command="vault-plugin-secrets-ejson"

# Enable the plugin at a specific path
$ vault secrets enable -path=ejson -plugin-name=vault-plugin-secrets-ejson plugin
Success! Enabled the vault-plugin-secrets-ejson plugin at: ejson/
```

### Demo

```bash
# Storing the public/private key for decryption
# This needs to be done first, and the secret must be underneath keys/
$ vault write ejson/keys/15838c2f3260185ad2a8e1298bd507479ff2470b9e9c1fd89e0fdfefe2959f56 private="37124bcf00c2d9fd87ddd596162d99c004460fd47130f2d653e45f85a0681cf0"
Key        Value
---        -----
private    37124bcf00c2d9fd87ddd596162d99c004460fd47130f2d653e45f85a0681cf0


$ cat itsasecret.ejson
{
  "_public_key": "15838c2f3260185ad2a8e1298bd507479ff2470b9e9c1fd89e0fdfefe2959f56",
  "asecret": "EJ[1:sdseJpJ3BpP9PO5Qs8IB4urmmYil46edSTek8SjgVGA=:zl7mkBzL4g2d0PE3hPucmfbDjf3aDK7K:iryi3H7wRGWvUI8kjfWLtP3sFiw=]",
  "anumber": 1
}

$ vault write ejson/itsasecret @itsasecret.ejson
Key      Value
---      -----
ejson    map[asecret:EJ[1:sdseJpJ3BpP9PO5Qs8IB4urmmYil46edSTek8SjgVGA=:zl7mkBzL4g2d0PE3hPucmfbDjf3aDK7K:iryi3H7wRGWvUI8kjfWLtP3sFiw=] _public_key:15838c2f3260185ad2a8e1298bd507479ff2470b9e9c1fd89e0fdfefe2959f56 anumber:1]

# Encrypted payload, useful for safely comparing values with other tools (e.g. Terraform)
$ vault read ejson/itsasecret
Key      Value
---      -----
ejson    map[asecret:EJ[1:sdseJpJ3BpP9PO5Qs8IB4urmmYil46edSTek8SjgVGA=:zl7mkBzL4g2d0PE3hPucmfbDjf3aDK7K:iryi3H7wRGWvUI8kjfWLtP3sFiw=] _public_key:15838c2f3260185ad2a8e1298bd507479ff2470b9e9c1fd89e0fdfefe2959f56 anumber:1]

# Decrypted payload, useful for consumption!
$ vault read ejson/itsasecret/decrypted
Key      Value
---      -----
ejson    map[anumber:1 asecret:ohai]
```

This plugin can also be used with Terraform's `vault_generic_secret` resource to safely store secrets inside of Vault.

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
    "anumber": 1
  }
}
EOT
}

# Initial apply
$ terraform apply -auto-approve
vault_generic_secret.example: Refreshing state... (ID: ejson/itsasecret)
vault_generic_secret.example: Creating...
  data_json:    "" => "{\"ejson\":{\"_public_key\":\"15838c2f3260185ad2a8e1298bd507479ff2470b9e9c1fd89e0fdfefe2959f56\",\"anumber\":1,\"database_password\":\"EJ[1:dPD6H7zfvJRwpJEIixW4HmZOSr+Mwi68Dtp0h+w5fAM=:lsAK/idjgbFagIWHIooBmVsTwFO1xr/1:cyzQwFGgAnMH24wVTwQKpSAw0V2vFQsD7x329g==]\",\"raptor\":\"EJ[1:VTS0QDPw4yD5324RDWWjD/m2rmgh5G+alvYTtb5jEjY=:BZso8xrFMssk/AuwfdjlQO/awyaB6E8D:mgT/mbESO2opyYAuK/buUe5XpHtu7MeLjLg=]\"}}"
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
