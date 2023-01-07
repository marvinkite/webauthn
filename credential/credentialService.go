package credential

type CredentialService interface {
	ExistsCredential(credentialId []byte) (bool, error)
	// GetCredential(credentialId []byte) (cred *webauthn.Credential, userId []byte, err error)
	// GetCredentialForUser(userId []byte) ([]webauthn.Credential, error)
}
