module github.com/go-ldap/ldap/v3

go 1.14

replace github.com/jcmturner/gokrb5/v8 v8.4.4 => github.com/sitnikovv/gokrb5/v8 v8.4.5-0.20240306063448-03360d80ce8a

require (
	github.com/Azure/go-ntlmssp v0.0.0-20221128193559-754e69321358
	github.com/alexbrainman/sspi v0.0.0-20231016080023-1a75b4708caa
	github.com/go-asn1-ber/asn1-ber v1.5.6
	github.com/google/uuid v1.6.0
	github.com/jcmturner/gokrb5/v8 v8.4.4
	github.com/stretchr/testify v1.8.1
	golang.org/x/net v0.23.0 // indirect
)
