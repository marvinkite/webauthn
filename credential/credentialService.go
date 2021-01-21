package credential

type CredentialService interface {
	ExistsCredential(credentialId []byte) bool
	GetCredential(credentialId []byte) (credential *Credential, userId []byte)
	GetCredentialForUser(userId []byte) []Credential
}
