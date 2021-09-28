package webauthn

import (
	"fmt"
	"github.com/marvinkite/webauthn/cbor_options"
	"github.com/marvinkite/webauthn/credential"
	"github.com/marvinkite/webauthn/metadata"
	"net/url"

	"github.com/marvinkite/webauthn/protocol"
)

var defaultTimeout = 60000

// WebAuthn is the primary interface of this package and contains the request handlers that should be called.
type WebAuthn struct {
	Config            *Config
	MetadataService   metadata.MetadataService
	CredentialService credential.CredentialService
	RpPolicy          protocol.RelyingPartyPolicy
}

type Timeouts struct {
	Registration   int
	Authentication int
}

// The config values required for proper
type Config struct {
	RPDisplayName string
	RPID          string
	RPOrigin      string
	RPIcon        string
	// Defaults for generating options
	AttestationPreference  protocol.ConveyancePreference
	AuthenticatorSelection protocol.AuthenticatorSelection

	Timeouts
	Debug bool
}

// Validate that the config flags in Config are properly set
func (config *Config) validate() error {
	if len(config.RPDisplayName) == 0 {
		return fmt.Errorf("Missing RPDisplayName")
	}

	if len(config.RPID) == 0 {
		return fmt.Errorf("Missing RPID")
	}

	_, err := url.Parse(config.RPID)
	if err != nil {
		return fmt.Errorf("RPID not valid URI: %+v", err)
	}

	if config.Timeouts.Authentication == 0 {
		config.Timeouts.Authentication = defaultTimeout
	}

	if config.Timeouts.Registration == 0 {
		config.Timeouts.Registration = defaultTimeout
	}

	if config.RPOrigin == "" {
		config.RPOrigin = config.RPID
	} else {
		u, err := url.Parse(config.RPOrigin)
		if err != nil {
			return fmt.Errorf("RPOrigin not valid URL: %+v", err)
		}
		config.RPOrigin = protocol.FullyQualifiedOrigin(u)
	}

	return nil
}

// Create a new WebAuthn object given the proper config flags
func New(config *Config, metadataService metadata.MetadataService, credentialService credential.CredentialService, rpPolicy protocol.RelyingPartyPolicy) (*WebAuthn, error) {
	if err := config.validate(); err != nil {
		return nil, fmt.Errorf("Configuration error: %+v", err)
	}
	if cbor_options.CborDecModeErr != nil {
		return nil, fmt.Errorf("Initilization error: %+v", cbor_options.CborDecModeErr)
	}
	if credentialService == nil {
		return nil, fmt.Errorf("CredentialService must not be nil")
	}
	if err := validateRelyingPartyPolicyRequirements(rpPolicy, metadataService); err != nil {
		return nil, fmt.Errorf("PolicyRequirements error: %+v", err)
	}

	return &WebAuthn{
		Config:            config,
		MetadataService:   metadataService,
		CredentialService: credentialService,
		RpPolicy:          rpPolicy,
	}, nil
}

func validateRelyingPartyPolicyRequirements(rpPolicy protocol.RelyingPartyPolicy, metadataService metadata.MetadataService) error {
	switch rpPolicy.(type) {
	case protocol.AllowAllPolicy:
		return nil
	case protocol.AllowlistPolicy:
		if metadataService == nil {
			return fmt.Errorf("MetadataService must be provided for AllowlistPolicy")
		}
	case protocol.AllowOnlyAuthenticatorFromMetadataServicePolicy:
		if metadataService == nil {
			return fmt.Errorf("MetadataService must be provided for AllowOnlyAuthenticatorFromMetadataServicePolicy")
		}
	}

	return nil
}
