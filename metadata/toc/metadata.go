package toc

import (
	"bytes"
	"crypto"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io/ioutil"
	"net/http"

	"github.com/cloudflare/cfssl/revoke"
	"github.com/marvinkite/webauthn/metadata"
	"github.com/mitchellh/mapstructure"

	"github.com/golang-jwt/jwt/v4"
)

var (
	errHashValueMismatch = &metadata.MetadataError{
		Type:    "hash_mismatch",
		Details: "Hash value mismatch between entry.Hash and downloaded bytes",
	}
	errIntermediateCertRevoked = &metadata.MetadataError{
		Type:    "intermediate_revoked",
		Details: "Intermediate certificate is on issuers revocation list",
	}
	errLeafCertRevoked = &metadata.MetadataError{
		Type:    "leaf_revoked",
		Details: "Leaf certificate is on issuers revocation list",
	}
	errCRLUnavailable = &metadata.MetadataError{
		Type:    "crl_unavailable",
		Details: "Certificate revocation list is unavailable",
	}
)

// ProcessMDSTOC processes a FIDO metadata table of contents object per §3.1.8, steps 1 through 5
// FIDO Authenticator Metadata Service
// https://fidoalliance.org/specs/fido-v2.0-rd-20180702/fido-metadata-service-v2.0-rd-20180702.html#metadata-toc-object-processing-rules
func ProcessMDSTOC(url string, suffix string, c http.Client) (metadata.MetadataTOCPayload, string, error) {
	var tocAlg string
	var payload metadata.MetadataTOCPayload
	// 1. The FIDO Server MUST be able to download the latest metadata TOC object from the well-known URL, when appropriate.
	body, err := downloadBytes(url+suffix, c)
	if err != nil {
		return payload, tocAlg, err
	}
	// Steps 2 - 4 done in unmarshalMDSTOC.  Caller is responsible for step 5.
	return unmarshalMDSTOC(body, c)
}

func unmarshalMDSTOC(body []byte, c http.Client) (metadata.MetadataTOCPayload, string, error) {
	var tocAlg string
	var payload metadata.MetadataTOCPayload
	token, err := jwt.Parse(string(body), func(token *jwt.Token) (interface{}, error) {
		// 2. If the x5u attribute is present in the JWT Header, then
		if _, ok := token.Header["x5u"].([]interface{}); ok {
			// never seen an x5u here, although it is in the spec
			return nil, errors.New("x5u encountered in header of metadata TOC payload")
		}
		var chain []interface{}
		// 3. If the x5u attribute is missing, the chain should be retrieved from the x5c attribute.

		if x5c, ok := token.Header["x5c"].([]interface{}); !ok {
			// If that attribute is missing as well, Metadata TOC signing trust anchor is considered the TOC signing certificate chain.
			root, err := getMetdataTOCSigningTrustAnchor(c)
			if nil != err {
				return nil, err
			}
			chain[0] = root
		} else {
			chain = x5c
		}

		// The certificate chain MUST be verified to properly chain to the metadata TOC signing trust anchor
		valid, err := validateChain(chain, c)
		if !valid || err != nil {
			return nil, err
		}
		// chain validated, extract the TOC signing certificate from the chain

		// create a buffer large enough to hold the certificate bytes
		o := make([]byte, base64.StdEncoding.DecodedLen(len(chain[0].(string))))
		// base64 decode the certificate into the buffer
		n, err := base64.StdEncoding.Decode(o, []byte(chain[0].(string)))
		if err != nil {
			return nil, err
		}
		// parse the certificate from the buffer
		cert, err := x509.ParseCertificate(o[:n])
		if err != nil {
			return nil, err
		}
		// 4. Verify the signature of the Metadata TOC object using the TOC signing certificate chain
		// jwt.Parse() uses the TOC signing certificate public key internally to verify the signature
		return cert.PublicKey, err
	})
	if err != nil {
		return payload, tocAlg, err
	}

	tocAlg = token.Header["alg"].(string)
	err = mapstructure.Decode(token.Claims, &payload)

	return payload, tocAlg, err
}

func getMetdataTOCSigningTrustAnchor(c http.Client) ([]byte, error) {
	rooturl := ""
	if metadata.Conformance {
		rooturl = "https://fidoalliance.co.nz/mds/pki/MDSROOT.crt"
	} else {
		rooturl = "https://mds.fidoalliance.org/Root.cer"
	}

	return downloadBytes(rooturl, c)
}

func validateChain(chain []interface{}, c http.Client) (bool, error) {
	root, err := getMetdataTOCSigningTrustAnchor(c)
	if err != nil {
		return false, err
	}

	roots := x509.NewCertPool()

	ok := roots.AppendCertsFromPEM(root)
	if !ok {
		return false, err
	}

	o := make([]byte, base64.StdEncoding.DecodedLen(len(chain[1].(string))))
	n, err := base64.StdEncoding.Decode(o, []byte(chain[1].(string)))
	if err != nil {
		return false, err
	}
	intcert, err := x509.ParseCertificate(o[:n])
	if err != nil {
		return false, err
	}

	if revoked, ok := revoke.VerifyCertificate(intcert); !ok {
		return false, errCRLUnavailable
	} else if revoked {
		return false, errIntermediateCertRevoked
	}

	ints := x509.NewCertPool()
	ints.AddCert(intcert)

	l := make([]byte, base64.StdEncoding.DecodedLen(len(chain[0].(string))))
	n, err = base64.StdEncoding.Decode(l, []byte(chain[0].(string)))
	if err != nil {
		return false, err
	}
	leafcert, err := x509.ParseCertificate(l[:n])
	if err != nil {
		return false, err
	}
	if revoked, ok := revoke.VerifyCertificate(leafcert); !ok {
		return false, errCRLUnavailable
	} else if revoked {
		return false, errLeafCertRevoked
	}

	opts := x509.VerifyOptions{
		Roots:         roots,
		Intermediates: ints,
	}
	_, err = leafcert.Verify(opts)
	return err == nil, err
}

// GetMetadataStatement iterates through a list of payload entries within a FIDO metadata table of contents object per §3.1.8, step 6
// FIDO Authenticator Metadata Service
// https://fidoalliance.org/specs/fido-v2.0-rd-20180702/fido-metadata-service-v2.0-rd-20180702.html#metadata-toc-object-processing-rules
func GetMetadataStatement(entry metadata.MetadataTOCPayloadEntry, suffix string, alg string, c http.Client) (metadata.MetadataStatement, error) {
	var statement metadata.MetadataStatement
	// 1. Ignore the entry if the AAID, AAGUID or attestationCertificateKeyIdentifiers is not relevant to the relying party (e.g. not acceptable by any policy)
	// Caller is responsible for determining if entry is relevant.

	// 2. Download the metadata statement from the URL specified by the field url.
	body, err := downloadBytes(entry.URL+suffix, c)
	if err != nil {
		return statement, err
	}
	// 3. Check whether the status report of the authenticator model has changed compared to the cached entry by looking at the fields timeOfLastStatusChange and statusReport.
	// Caller is responsible for cache

	// step 4 done in unmarshalMetadataStatement, caller is responsible for step 5
	return unmarshalMetadataStatement(body, entry.Hash)
}

func unmarshalMetadataStatement(body []byte, hash string) (metadata.MetadataStatement, error) {
	// 4. Compute the hash value of the metadata statement downloaded from the URL and verify the hash value to the hash specified in the field hash of the metadata TOC object.
	var statement metadata.MetadataStatement

	entryHash, err := base64.URLEncoding.DecodeString(hash)
	if err != nil {
		entryHash, err = base64.RawURLEncoding.DecodeString(hash)
	}
	if err != nil {
		return statement, err
	}

	// TODO: Get hasher based on MDS TOC alg instead of assuming SHA256
	hasher := crypto.SHA256.New()
	_, _ = hasher.Write(body)
	hashed := hasher.Sum(nil)
	// Ignore the downloaded metadata statement if the hash value doesn't match.
	if !bytes.Equal(hashed, entryHash) {
		return statement, errHashValueMismatch
	}

	// Extract the metadata statement from base64 encoded form
	n := base64.URLEncoding.DecodedLen(len(body))
	out := make([]byte, n)
	m, err := base64.URLEncoding.Decode(out, body)
	if err != nil {
		return statement, err
	}
	// Unmarshal the metadata statement into a MetadataStatement structure and return it to caller
	err = json.Unmarshal(out[:m], &statement)
	return statement, err
}

func downloadBytes(url string, c http.Client) ([]byte, error) {
	res, err := c.Get(url)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()
	body, _ := ioutil.ReadAll(res.Body)
	return body, err
}
