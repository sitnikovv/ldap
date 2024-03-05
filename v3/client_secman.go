package ldap

import ber "github.com/go-asn1-ber/asn1-ber"

type ClientExtended interface {
	Client
	Extended(extendedRequest *ExtendedRequest) (*ber.Packet, error)
}
