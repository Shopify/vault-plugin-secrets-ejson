package main

import (
	"os"

	ejson "github.com/Shopify/vault-plugin-secrets-ejson"
	"github.com/hashicorp/go-hclog"
	"github.com/hashicorp/vault/api"
	"github.com/hashicorp/vault/sdk/logical"
	"github.com/hashicorp/vault/sdk/plugin"
)

func main() {
	apiClientMeta := &api.PluginAPIClientMeta{}
	flags := apiClientMeta.FlagSet()
	flags.Parse(os.Args[1:]) // Ignore command, strictly parse flags

	tlsConfig := apiClientMeta.GetTLSConfig()
	tlsProviderFunc := api.VaultPluginTLSProvider(tlsConfig)

	factoryFunc := ejson.FactoryType(logical.TypeLogical)

	err := plugin.Serve(&plugin.ServeOpts{
		BackendFactoryFunc: factoryFunc,
		TLSProviderFunc:    tlsProviderFunc,
	})
	if err != nil {
		log := hclog.New(&hclog.LoggerOptions{})
		log.Error("plugin shutting down", "error", err)
		os.Exit(1)
	}
}
