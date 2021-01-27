package webauthn

import (
	"gitlab.com/hanko/webauthn/credential"
	"gitlab.com/hanko/webauthn/protocol"
)

// MakeNewCredential will return a credential pointer on successful validation of a registration response
func MakeNewCredential(c *protocol.ParsedCredentialCreationData, userId []byte) (*credential.Credential, error) {

	newCredential := &credential.Credential{
		ID:              c.Response.AttestationObject.AuthData.AttData.CredentialID,
		PublicKey:       c.Response.AttestationObject.AuthData.AttData.CredentialPublicKey,
		AttestationType: c.Response.AttestationObject.Format,
		Authenticator: credential.Authenticator{
			AAGUID:    c.Response.AttestationObject.AuthData.AttData.AAGUID,
			SignCount: c.Response.AttestationObject.AuthData.Counter,
		},
		UserId: userId,
	}

	return newCredential, nil
}
