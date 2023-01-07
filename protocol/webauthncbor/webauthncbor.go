package webauthncbor

import "github.com/fxamacker/cbor/v2"

const nestedLevelsAllowed = 4

// ctap2CBORDecMode is the cbor.DecMode following the CTAP2 canonical CBOR encoding form
// (https://fidoalliance.org/specs/fido-v2.0-ps-20190130/fido-client-to-authenticator-protocol-v2.0-ps-20190130.html#message-encoding)
var ctap2CBORDecMode, _ = cbor.DecOptions{
	DupMapKey:       cbor.DupMapKeyEnforcedAPF,
	TimeTag:         cbor.DecTagIgnored,
	MaxNestedLevels: nestedLevelsAllowed,
	IndefLength:     cbor.IndefLengthForbidden,
	TagsMd:          cbor.TagsForbidden,
}.DecMode()

var ctap2CBOREncMode, _ = cbor.CTAP2EncOptions().EncMode()

// Unmarshal parses the CBOR-encoded data into the value pointed to by v
// following the CTAP2 canonical CBOR encoding form.
// (https://fidoalliance.org/specs/fido-v2.0-ps-20190130/fido-client-to-authenticator-protocol-v2.0-ps-20190130.html#message-encoding)
func Unmarshal(data []byte, v interface{}) error {
	return ctap2CBORDecMode.Unmarshal(data, v)
}

// Marshal encodes the value pointed to by v
// following the CTAP2 canonical CBOR encoding form.
// (https://fidoalliance.org/specs/fido-v2.0-ps-20190130/fido-client-to-authenticator-protocol-v2.0-ps-20190130.html#message-encoding)
func Marshal(v interface{}) ([]byte, error) {
	return ctap2CBOREncMode.Marshal(v)
}
