package credential

type CredentialService interface {
	ExistsCredential(credentialId []byte) bool
	GetCredential(credentialId []byte) (cred *Credential, userId []byte)
	GetCredentialForUser(userId []byte) []Credential
}
