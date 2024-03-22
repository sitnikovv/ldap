package gssapi

import (
	"github.com/jcmturner/gokrb5/v8/client"
	"github.com/jcmturner/gokrb5/v8/config"
	"github.com/jcmturner/gokrb5/v8/credentials"
	"github.com/jcmturner/gokrb5/v8/keytab"
)

// NewClientWithKeytabNoPath creates a new client from a keytab credential without keytab and config paths.
// Set the realm to empty string to use the default realm from config.
func NewClientWithKeytabNoPath(username, realm string, keytab *keytab.Keytab, krb5conf *config.Config, settings ...func(*client.Settings)) (*Client, error) {
	keytabClient := client.NewWithKeytab(username, realm, keytab, krb5conf, settings...)

	return &Client{
		Client: keytabClient,
	}, nil
}

// NewClientWithPasswordNoPath creates a new client from a password credential without config paths.
// Set the realm to empty string to use the default realm from config.
func NewClientWithPasswordNoPath(username, realm, password string, krb5conf *config.Config, settings ...func(*client.Settings)) (*Client, error) {
	passwordClient := client.NewWithPassword(username, realm, password, krb5conf, settings...)

	return &Client{
		Client: passwordClient,
	}, nil
}

// NewClientFromCCacheNoPath creates a new client from a populated client cache without ccache and config paths.
func NewClientFromCCacheNoPath(ccache *credentials.CCache, krb5conf *config.Config, settings ...func(*client.Settings)) (*Client, error) {
	cacheClient, err := client.NewFromCCache(ccache, krb5conf, settings...)
	if err != nil {
		return nil, err
	}

	return &Client{
		Client: cacheClient,
	}, nil
}
