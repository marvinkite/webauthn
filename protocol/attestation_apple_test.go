package protocol

import (
	"crypto/sha256"
	"strings"
	"testing"

	"github.com/marvinkite/webauthn/metadata"
)

func Test_verifyAppleAttestationFormat(t *testing.T) {
	pcc, err := ParseCredentialCreationResponseBody(strings.NewReader(registrationResponse))
	if err != nil {
		t.Error(err)
		return
	}
	clientDataHash := sha256.Sum256(pcc.Raw.AttestationResponse.ClientDataJSON)

	type args struct {
		att            AttestationObject
		clientDataHash []byte
	}
	tests := []struct {
		name    string
		args    args
		wantErr bool
	}{
		{
			name: "Certificate outdated",
			args: args{
				att:            pcc.Response.AttestationObject,
				clientDataHash: clientDataHash[:],
			},
			wantErr: true,
		},
		{
			name: "Nonce not equal",
			args: args{
				att:            pcc.Response.AttestationObject,
				clientDataHash: []byte{1, 2, 3, 4, 5},
			},
			wantErr: true,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			attestationType, x5c, err := verifyAppleAttestationFormat(test.args.att, test.args.clientDataHash)
			if (err != nil) != test.wantErr {
				t.Errorf("verifyAppleAttestationFormat() error = %v, wantErr %v", err, test.wantErr)
				return
			}

			if attestationType != "apple" {
				t.Errorf("attestationType must be 'apple', got = '%s'", attestationType)
			}

			if err == nil && len(x5c) != 2 {
				t.Errorf("The returned x5c chain must have a length of 2, got = %d", len(x5c))
			}
		})
	}
}

func Test_verifyAppleFormat(t *testing.T) {
	type args struct {
		att            AttestationObject
		clientDataHash []byte
	}
	successAttResponse := attestationTestUnpackResponse(t, appleTestResponse["success"]).Response.AttestationObject
	successClientDataHash := sha256.Sum256(attestationTestUnpackResponse(t, appleTestResponse["success"]).Raw.AttestationResponse.ClientDataJSON)
	tests := []struct {
		name    string
		args    args
		want    string
		want1   []interface{}
		wantErr bool
	}{
		{
			"success",
			args{
				successAttResponse,
				successClientDataHash[:],
			},
			string(metadata.AnonCA),
			nil,
			false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, _, err := verifyAppleAttestationFormat(tt.args.att, tt.args.clientDataHash)
			if (err != nil) != tt.wantErr {
				t.Errorf("verifyAppleFormat() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("verifyAppleFormat() got = %v, want %v", got, tt.want)
			}
			// if !reflect.DeepEqual(got1, tt.want1) {
			//	t.Errorf("verifyPackedFormat() got1 = %v, want %v", got1, tt.want1)
			// }
		})
	}
}

var appleTestResponse = map[string]string{
	`success`: `{
		"rawId": "U5cxFNxLbU9-SAi1K7k9atYwXhghkAMbxpL__VPtBlw",
		"id": "U5cxFNxLbU9-SAi1K7k9atYwXhghkAMbxpL__VPtBlw",
		"response": {
		  "clientDataJSON": "eyJ0eXBlIjoid2ViYXV0aG4uY3JlYXRlIiwiY2hhbGxlbmdlIjoia093TXZFMm1RTzZvdTBCMGpqRDBWQSIsIm9yaWdpbiI6Imh0dHBzOi8vNmNjM2M5ZTc5NjdhLm5ncm9rLmlvIn0",
		  "attestationObject": "o2NmbXRlYXBwbGVnYXR0U3RtdKJjYWxnJmN4NWOCWQJIMIICRDCCAcmgAwIBAgIGAXUCfWGDMAoGCCqGSM49BAMCMEgxHDAaBgNVBAMME0FwcGxlIFdlYkF1dGhuIENBIDExEzARBgNVBAoMCkFwcGxlIEluYy4xEzARBgNVBAgMCkNhbGlmb3JuaWEwHhcNMjAxMDA3MDk0NjEyWhcNMjAxMDA4MDk1NjEyWjCBkTFJMEcGA1UEAwxANjEyNzZmYzAyZDNmZThkMTZiMzNiNTU0OWQ4MTkyMzZjODE3NDZhODNmMmU5NGE2ZTRiZWUxYzcwZjgxYjViYzEaMBgGA1UECwwRQUFBIENlcnRpZmljYXRpb24xEzARBgNVBAoMCkFwcGxlIEluYy4xEzARBgNVBAgMCkNhbGlmb3JuaWEwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAAR5_lkIu1EpyAk4t1TATSs0DvpmFbmHaYv1naTlPqPm_vsD2qEnDVgE6KthwVqsokNcfb82nXHKFcUjsABKG3W3o1UwUzAMBgNVHRMBAf8EAjAAMA4GA1UdDwEB_wQEAwIE8DAzBgkqhkiG92NkCAIEJjAkoSIEIJxgAhVAs-GYNN_jfsYkRcieGylPeSzka5QTwyMO84aBMAoGCCqGSM49BAMCA2kAMGYCMQDaHBjrI75xAF7SXzyF5zSQB_Lg9PjTdyye-w7stiqy84K6lmo8d3fIptYjLQx81bsCMQCvC8MSN-aewiaU0bMsdxRbdDerCJJj3xJb3KZwloevJ3daCmCcrZrAPYfLp2kDOshZAjgwggI0MIIBuqADAgECAhBWJVOVx6f7QOviKNgmCFO2MAoGCCqGSM49BAMDMEsxHzAdBgNVBAMMFkFwcGxlIFdlYkF1dGhuIFJvb3QgQ0ExEzARBgNVBAoMCkFwcGxlIEluYy4xEzARBgNVBAgMCkNhbGlmb3JuaWEwHhcNMjAwMzE4MTgzODAxWhcNMzAwMzEzMDAwMDAwWjBIMRwwGgYDVQQDDBNBcHBsZSBXZWJBdXRobiBDQSAxMRMwEQYDVQQKDApBcHBsZSBJbmMuMRMwEQYDVQQIDApDYWxpZm9ybmlhMHYwEAYHKoZIzj0CAQYFK4EEACIDYgAEgy6HLyYUkYECJbn1_Na7Y3i19V8_ywRbxzWZNHX9VJBE35v-GSEXZcaaHdoFCzjUUINAGkNPsk0RLVbD4c-_y5iR_sBpYIG--Wy8d8iN3a9Gpa7h3VFbWvqrk76cCyaRo2YwZDASBgNVHRMBAf8ECDAGAQH_AgEAMB8GA1UdIwQYMBaAFCbXZNnFeMJaZ9Gn3msS0Btj8cbXMB0GA1UdDgQWBBTrroLE_6GsW1HUzyRhBQC-Y713iDAOBgNVHQ8BAf8EBAMCAQYwCgYIKoZIzj0EAwMDaAAwZQIxAN2LGjSBpfrZ27TnZXuEHhRMJ7dbh2pBhsKxR1dQM3In7-VURX72SJUMYy5cSD5wwQIwLIpgRNwgH8_lm8NNKTDBSHhR2WDtanXx60rKvjjNJbiX0MgFvvDH94sHpXHG6A4HaGF1dGhEYXRhWJhWHo8_bWPQzAMKYRIrGXu__PkMUfuqHM4RH7Jea4WDgkUAAAAAAAAAAAAAAAAAAAAAAAAAAAAUomGfdaNI-cYgWrq2klNk97zkcg-lAQIDJiABIVggef5ZCLtRKcgJOLdUwE0rNA76ZhW5h2mL9Z2k5T6j5v4iWCD7A9qhJw1YBOirYcFarKJDXH2_Np1xyhXFI7AASht1tw"},
		"type": "public-key"
	  }`,
}

var registrationResponse = `{
    "id": "JLZzQBSjyq0DofZme1kp7b0zecI",
    "rawId": "JLZzQBSjyq0DofZme1kp7b0zecI",
    "type": "public-key",
    "response": {
        "attestationObject": "o2NmbXRlYXBwbGVnYXR0U3RtdKFjeDVjglkCSDCCAkQwggHJoAMCAQICBgF3KWdGgDAKBggqhkjOPQQDAjBIMRwwGgYDVQQDDBNBcHBsZSBXZWJBdXRobiBDQSAxMRMwEQYDVQQKDApBcHBsZSBJbmMuMRMwEQYDVQQIDApDYWxpZm9ybmlhMB4XDTIxMDEyMTA5MjI1MFoXDTIxMDEyNDA5MjI1MFowgZExSTBHBgNVBAMMQDFmNmZjMDhkOTJlODA1NzQ3NmNkNWE3YWQ3OTJiNzRhZWU5Y2MwNTlmNGMwNmVjMjA1OTQ3NmY4M2NmOWRjYzExGjAYBgNVBAsMEUFBQSBDZXJ0aWZpY2F0aW9uMRMwEQYDVQQKDApBcHBsZSBJbmMuMRMwEQYDVQQIDApDYWxpZm9ybmlhMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAERO0WnPVCWzg93XhoyQMz9el0r_O-Zs0TlI8ZDpgMG5UuNTaPRS2l6W_M_OTpmZk_sK8dgbRQW55TxrWbwSIqJ6NVMFMwDAYDVR0TAQH_BAIwADAOBgNVHQ8BAf8EBAMCBPAwMwYJKoZIhvdjZAgCBCYwJKEiBCB7SSwpqiJN8OqAw99S5JOrirjG1E_bhOu1UPkkObWxAjAKBggqhkjOPQQDAgNpADBmAjEAvtZyPGTuXedx1DVFmy2IZWS8gwGIqA68HY9kpDNI68YEdOdVjNo-XWtudZNo9ClaAjEA8VuShDAM_yMaqEbNEx3vttr_eYXTgfIvLFqAKzEqH70icLcvBJfAMFoa_ogd-3GhWQI4MIICNDCCAbqgAwIBAgIQViVTlcen-0Dr4ijYJghTtjAKBggqhkjOPQQDAzBLMR8wHQYDVQQDDBZBcHBsZSBXZWJBdXRobiBSb290IENBMRMwEQYDVQQKDApBcHBsZSBJbmMuMRMwEQYDVQQIDApDYWxpZm9ybmlhMB4XDTIwMDMxODE4MzgwMVoXDTMwMDMxMzAwMDAwMFowSDEcMBoGA1UEAwwTQXBwbGUgV2ViQXV0aG4gQ0EgMTETMBEGA1UECgwKQXBwbGUgSW5jLjETMBEGA1UECAwKQ2FsaWZvcm5pYTB2MBAGByqGSM49AgEGBSuBBAAiA2IABIMuhy8mFJGBAiW59fzWu2N4tfVfP8sEW8c1mTR1_VSQRN-b_hkhF2XGmh3aBQs41FCDQBpDT7JNES1Ww-HPv8uYkf7AaWCBvvlsvHfIjd2vRqWu4d1RW1r6q5O-nAsmkaNmMGQwEgYDVR0TAQH_BAgwBgEB_wIBADAfBgNVHSMEGDAWgBQm12TZxXjCWmfRp95rEtAbY_HG1zAdBgNVHQ4EFgQU666CxP-hrFtR1M8kYQUAvmO9d4gwDgYDVR0PAQH_BAQDAgEGMAoGCCqGSM49BAMDA2gAMGUCMQDdixo0gaX62du052V7hB4UTCe3W4dqQYbCsUdXUDNyJ-_lVEV-9kiVDGMuXEg-cMECMCyKYETcIB_P5ZvDTSkwwUh4Udlg7Wp18etKyr44zSW4l9DIBb7wx_eLB6VxxugOB2hhdXRoRGF0YViYdKbqkhPJnC90siSSsyDPQCYqlMGpUKA5fyklC2CEHvBFAAAAAAAAAAAAAAAAAAAAAAAAAAAAFCS2c0AUo8qtA6H2ZntZKe29M3nCpQECAyYgASFYIETtFpz1Qls4Pd14aMkDM_XpdK_zvmbNE5SPGQ6YDBuVIlggLjU2j0UtpelvzPzk6ZmZP7CvHYG0UFueU8a1m8EiKic",
        "clientDataJSON": "eyJ0eXBlIjoid2ViYXV0aG4uY3JlYXRlIiwiY2hhbGxlbmdlIjoiMnJXNVkxNmpiYVV1aUlka29YMzNzV3FZQWdLclYxLVJZbVhkQlRVTE1lOCIsIm9yaWdpbiI6Imh0dHBzOi8vd2ViYXV0aG4uaW8ifQ"
    }
}`
