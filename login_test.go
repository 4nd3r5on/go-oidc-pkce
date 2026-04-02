package oidcpkce_test

import (
	"context"
	"testing"

	oidcpkce "github.com/4nd3r5on/go-oidc-pkce"
)

func TestDefaultValidateRedirectURI(t *testing.T) {
	cases := []struct {
		uri     string
		wantErr bool
	}{
		// valid: relative paths
		{"", false},
		{"/", false},
		{"/dashboard", false},
		{"/path?q=1", false},
		{"/path?q=1#fragment", false},
		{"/deep/nested/path", false},

		// invalid: absolute URLs
		{"https://evil.com", true},
		{"http://evil.com/path", true},
		{"ftp://files.example.com", true},

		// invalid: protocol-relative (host is set, scheme is empty)
		{"//evil.com", true},
		{"//evil.com/path", true},

		// invalid: schemes that don't carry a host
		{"javascript:alert(1)", true},
		{"data:text/html,<h1>hi</h1>", true},

		// url.Parse does not normalise backslashes, but browsers do:
		// \\evil.com → https://evil.com. Rejected explicitly.
		{"\\\\evil.com", true},
	}

	for _, tc := range cases {
		t.Run(tc.uri, func(t *testing.T) {
			err := oidcpkce.DefaultValidateRedirectURI(context.Background(), tc.uri)
			if tc.wantErr && err == nil {
				t.Errorf("uri %q: expected error, got nil", tc.uri)
			}
			if !tc.wantErr && err != nil {
				t.Errorf("uri %q: expected nil, got %v", tc.uri, err)
			}
		})
	}
}
