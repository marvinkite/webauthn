package cbor_options

import "github.com/fxamacker/cbor/v2"

var (
	cborDecOptions = cbor.DecOptions{
		DupMapKey:       cbor.DupMapKeyEnforcedAPF,
		TimeTag:         cbor.DecTagIgnored,
		MaxNestedLevels: 4,
		IndefLength:     cbor.IndefLengthForbidden,
		TagsMd:          cbor.TagsForbidden,
	}

	CborDecMode, CborDecModeErr = cborDecOptions.DecMode()
)
