package oidcpkce

import (
	"context"
	"fmt"

	"github.com/coreos/go-oidc"
	"golang.org/x/oauth2"
)

// Provider wires one OIDC provider (e.g. Authentik, Zitadel, Auth0) to the three
// stateful interfaces above. Safe for concurrent use after construction.
type Provider[ClaimsT HasNonce] struct {
	oidcProvider *oidc.Provider
	verifier     *oidc.IDTokenVerifier
	oauth2Cfg    oauth2.Config

	providerName string // stored on the user record, e.g. "authentik"

	states   StateStore
	users    UserStore[ClaimsT]
	sessions SessionIssuer
}

func NewProvider[ClaimsT HasNonce](
	ctx context.Context,
	issuerURL, clientID, clientSecret, redirectURL string,
	providerName string,
	states StateStore,
	users UserStore[ClaimsT],
	sessions SessionIssuer,
) (*Provider[ClaimsT], error) {
	p, err := oidc.NewProvider(ctx, issuerURL)
	if err != nil {
		return nil, fmt.Errorf("oidc discovery %q: %w", issuerURL, err)
	}

	return &Provider[ClaimsT]{
		oidcProvider: p,
		// go-oidc Verify() checks: signature (JWKS + rotation), iss, aud, exp, iat.
		verifier: p.Verifier(&oidc.Config{ClientID: clientID}),
		oauth2Cfg: oauth2.Config{
			ClientID:     clientID,
			ClientSecret: clientSecret,
			RedirectURL:  redirectURL,
			Endpoint:     p.Endpoint(),
			Scopes:       []string{oidc.ScopeOpenID, "profile", "email"},
		},
		providerName: providerName,
		states:       states,
		users:        users,
		sessions:     sessions,
	}, nil
}
