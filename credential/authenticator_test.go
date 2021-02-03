package credential

import (
	"testing"
)

func TestAuthenticator_UpdateCounter(t *testing.T) {
	type fields struct {
		AAGUID    []byte
		SignCount uint32
	}
	type args struct {
		authDataCount uint32
	}
	tests := []struct {
		name      string
		fields    fields
		args      args
		wantError bool
	}{
		{
			"Increased counter",
			fields{
				AAGUID:    make([]byte, 16),
				SignCount: 1,
			},
			args{
				authDataCount: 2,
			},
			false,
		},
		{
			"Unchanged counter",
			fields{
				AAGUID:    make([]byte, 16),
				SignCount: 1,
			},
			args{
				authDataCount: 1,
			},
			true,
		},
		{
			"Decreased counter",
			fields{
				AAGUID:    make([]byte, 16),
				SignCount: 2,
			},
			args{
				authDataCount: 1,
			},
			true,
		},
		{
			"Zero counter",
			fields{
				AAGUID:    make([]byte, 16),
				SignCount: 0,
			},
			args{
				authDataCount: 0,
			},
			false,
		},
		{
			"Counter returned to zero",
			fields{
				AAGUID:    make([]byte, 16),
				SignCount: 1,
			},
			args{
				authDataCount: 0,
			},
			true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a := &Authenticator{
				AAGUID:    tt.fields.AAGUID,
				SignCount: tt.fields.SignCount,
			}
			err := a.CheckCounter(tt.args.authDataCount)
			a.UpdateCounter(tt.args.authDataCount)
			if (err != nil) != tt.wantError {
				t.Errorf("Clone warning result [%v] does not match expectation: [%v]", err != nil, tt.wantError)
				return
			}
		})
	}
}
