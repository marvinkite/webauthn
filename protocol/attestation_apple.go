package protocol

import (
	"bytes"
	"crypto/sha256"
	"crypto/x509"
	"fmt"
	"time"
)

var appleAttestationKey = "apple"

func init() {
	RegisterAttestationFormat(appleAttestationKey, verifyAppleAttestationFormat)
}

// From §8.8. https://www.w3.org/TR/webauthn/#sctn-apple-anonymous-attestation
// The apple attestation statement looks like:
// appleStmtFormat = {
// x5c: [credCert: bytes, * (caCert: bytes)]
// }

func verifyAppleAttestationFormat(att AttestationObject, clientDataHash []byte) (string, []interface{}, error) {
	// Step 1. Verify that attStmt is valid CBOR conforming to the syntax defined above and perform CBOR decoding
	// on it to extract the contained fields.
	x5c, x5cPresent := att.AttStatement["x5c"].([]interface{})
	if !x5cPresent {
		return appleAttestationKey, nil, ErrAttestationFormat.WithDetails("Error retrieving x5c value")
	}

	certChain, err := parseCertificateChain(x5c)
	if err != nil {
		return appleAttestationKey, nil, err
	}
	if certChain == nil || len(certChain) == 0 {
		return "", nil, ErrAttestationFormat.WithDetails("No Certificates found in certificate chain")
	}

	// Step 2. Concatenate authenticatorData and clientDataHash to form nonceToHash
	nonceToHash := make([]byte, 0)
	nonceToHash = append(nonceToHash, att.RawAuthData...)
	nonceToHash = append(nonceToHash, clientDataHash...)

	// Step 3. Perform SHA-256 hash of nonceToHash to produce nonce.
	nonce := sha256.Sum256(nonceToHash)

	// Step 4. Verify that nonce equals the value of the extension with OID 1.2.840.113635.100.8.2 in credCert.
	var nonceInCredCertVerified bool
	credCert := certChain[0]
	for _, ext := range credCert.Extensions {
		if ext.Id.String() == "1.2.840.113635.100.8.2" {
			asn1Structure, extensionNonce := ext.Value[:6], ext.Value[6:]
			// ASN.1 DER Structure
			// 0x30: TAG = SEQUENCE OF
			// 0x24: Length = 36 bytes
			// 0xA1: TAG = Context Specific TAG
			// 0x22: Length = 34 bytes
			// 0x04: TAG = Octet String
			// 0x20: Length = 32 bytes
			if bytes.Equal(asn1Structure, []byte{0x30, 0x24, 0xA1, 0x22, 0x04, 0x20}) {
				if bytes.Equal(extensionNonce, nonce[:]) {
					nonceInCredCertVerified = true
				}
			}
		}
	}
	if !nonceInCredCertVerified {
		return appleAttestationKey, nil, ErrAttestationCertificate.WithDetails("Nonce is not in certificate extension")
	}

	// Step 5. Verify that the credential public key equals the Subject Public Key of credCert.
	// TODO: doesn't work !!!
	publicKeyBytes, err := x509.MarshalPKIXPublicKey(credCert.PublicKey)
	if !bytes.Equal(publicKeyBytes, att.AuthData.AttData.CredentialPublicKey) {
		return appleAttestationKey, x5c, ErrAttestationCertificate.WithDetails("Certificate Public Key do not match AuthenticatorData.AttestedCredentialData.CredentialPublicKey")
	}

	// Step 6. If successful, return implementation-specific values representing attestation type Anonymization CA and
	// attestation trust path x5c.
	return appleAttestationKey, x5c, nil
}

func parseCertificateChain(x5c []interface{}) ([]x509.Certificate, error) {
	var certChain []x509.Certificate
	for _, c := range x5c {
		cb, cv := c.([]byte)
		if !cv {
			return nil, ErrAttestation.WithDetails("Error getting certificate from x5c certificate chain")
		}
		ct, err := x509.ParseCertificate(cb)
		if err != nil {
			return nil, ErrAttestationFormat.WithDetails(fmt.Sprintf("Error parsing certificate from ASN.1 data: %v", err))
		}
		if ct.NotBefore.After(time.Now()) || ct.NotAfter.Before(time.Now()) {
			return nil, ErrAttestationFormat.WithDetails("Certificate in chain not time valid")
		}

		certChain = append(certChain, *ct)
	}

	return certChain, nil
}
