package protocol

import (
	"crypto/sha256"
	"strings"
	"testing"
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
			name: "Successful Self Attestation",
			args: args{
				att:            pcc.Response.AttestationObject,
				clientDataHash: clientDataHash[:],
			},
			wantErr: false,
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

var userId = "losLAAAAAAAAAA=="
var attestation = "direct"
var challenge = "2rW5Y16jbaUuiIdkoX33sWqYAgKrV1+RYmXdBTULMe8="
var registrationResponse = `{"id":"JLZzQBSjyq0DofZme1kp7b0zecI","rawId":"JLZzQBSjyq0DofZme1kp7b0zecI","type":"public-key","response":{"attestationObject":"o2NmbXRlYXBwbGVnYXR0U3RtdKFjeDVjglkCSDCCAkQwggHJoAMCAQICBgF3KWdGgDAKBggqhkjOPQQDAjBIMRwwGgYDVQQDDBNBcHBsZSBXZWJBdXRobiBDQSAxMRMwEQYDVQQKDApBcHBsZSBJbmMuMRMwEQYDVQQIDApDYWxpZm9ybmlhMB4XDTIxMDEyMTA5MjI1MFoXDTIxMDEyNDA5MjI1MFowgZExSTBHBgNVBAMMQDFmNmZjMDhkOTJlODA1NzQ3NmNkNWE3YWQ3OTJiNzRhZWU5Y2MwNTlmNGMwNmVjMjA1OTQ3NmY4M2NmOWRjYzExGjAYBgNVBAsMEUFBQSBDZXJ0aWZpY2F0aW9uMRMwEQYDVQQKDApBcHBsZSBJbmMuMRMwEQYDVQQIDApDYWxpZm9ybmlhMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAERO0WnPVCWzg93XhoyQMz9el0r_O-Zs0TlI8ZDpgMG5UuNTaPRS2l6W_M_OTpmZk_sK8dgbRQW55TxrWbwSIqJ6NVMFMwDAYDVR0TAQH_BAIwADAOBgNVHQ8BAf8EBAMCBPAwMwYJKoZIhvdjZAgCBCYwJKEiBCB7SSwpqiJN8OqAw99S5JOrirjG1E_bhOu1UPkkObWxAjAKBggqhkjOPQQDAgNpADBmAjEAvtZyPGTuXedx1DVFmy2IZWS8gwGIqA68HY9kpDNI68YEdOdVjNo-XWtudZNo9ClaAjEA8VuShDAM_yMaqEbNEx3vttr_eYXTgfIvLFqAKzEqH70icLcvBJfAMFoa_ogd-3GhWQI4MIICNDCCAbqgAwIBAgIQViVTlcen-0Dr4ijYJghTtjAKBggqhkjOPQQDAzBLMR8wHQYDVQQDDBZBcHBsZSBXZWJBdXRobiBSb290IENBMRMwEQYDVQQKDApBcHBsZSBJbmMuMRMwEQYDVQQIDApDYWxpZm9ybmlhMB4XDTIwMDMxODE4MzgwMVoXDTMwMDMxMzAwMDAwMFowSDEcMBoGA1UEAwwTQXBwbGUgV2ViQXV0aG4gQ0EgMTETMBEGA1UECgwKQXBwbGUgSW5jLjETMBEGA1UECAwKQ2FsaWZvcm5pYTB2MBAGByqGSM49AgEGBSuBBAAiA2IABIMuhy8mFJGBAiW59fzWu2N4tfVfP8sEW8c1mTR1_VSQRN-b_hkhF2XGmh3aBQs41FCDQBpDT7JNES1Ww-HPv8uYkf7AaWCBvvlsvHfIjd2vRqWu4d1RW1r6q5O-nAsmkaNmMGQwEgYDVR0TAQH_BAgwBgEB_wIBADAfBgNVHSMEGDAWgBQm12TZxXjCWmfRp95rEtAbY_HG1zAdBgNVHQ4EFgQU666CxP-hrFtR1M8kYQUAvmO9d4gwDgYDVR0PAQH_BAQDAgEGMAoGCCqGSM49BAMDA2gAMGUCMQDdixo0gaX62du052V7hB4UTCe3W4dqQYbCsUdXUDNyJ-_lVEV-9kiVDGMuXEg-cMECMCyKYETcIB_P5ZvDTSkwwUh4Udlg7Wp18etKyr44zSW4l9DIBb7wx_eLB6VxxugOB2hhdXRoRGF0YViYdKbqkhPJnC90siSSsyDPQCYqlMGpUKA5fyklC2CEHvBFAAAAAAAAAAAAAAAAAAAAAAAAAAAAFCS2c0AUo8qtA6H2ZntZKe29M3nCpQECAyYgASFYIETtFpz1Qls4Pd14aMkDM_XpdK_zvmbNE5SPGQ6YDBuVIlggLjU2j0UtpelvzPzk6ZmZP7CvHYG0UFueU8a1m8EiKic","clientDataJSON":"eyJ0eXBlIjoid2ViYXV0aG4uY3JlYXRlIiwiY2hhbGxlbmdlIjoiMnJXNVkxNmpiYVV1aUlka29YMzNzV3FZQWdLclYxLVJZbVhkQlRVTE1lOCIsIm9yaWdpbiI6Imh0dHBzOi8vd2ViYXV0aG4uaW8ifQ"}}`
