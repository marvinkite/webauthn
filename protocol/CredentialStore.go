package protocol

type CredentialStore interface {
	ExistsCredential(credentialId []byte) bool
}