package webauthn

import (
	"github.com/marvinkite/webauthn/credential"
	"reflect"
	"testing"

	"github.com/marvinkite/webauthn/protocol"
)

func TestMakeNewCredential(t *testing.T) {
	type args struct {
		c *protocol.ParsedCredentialCreationData
	}
	tests := []struct {
		name    string
		args    args
		want    *credential.Credential
		wantErr bool
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := MakeNewCredential(tt.args.c)
			if (err != nil) != tt.wantErr {
				t.Errorf("MakeNewCredential() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("MakeNewCredential() = %v, want %v", got, tt.want)
			}
		})
	}
}
