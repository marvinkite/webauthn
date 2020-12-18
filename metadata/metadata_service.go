package metadata

type MetadataService interface {
	WebAuthnAuthenticator(aaguid string) *MetadataStatement
	U2FAuthenticator(attestationCertificateKeyIdentifier string) *MetadataStatement
}