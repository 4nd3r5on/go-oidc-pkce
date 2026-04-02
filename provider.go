package oidcpkce

import (
	"context"
	"fmt"

	"github.com/coreos/go-oidc"
	"golang.org/x/oauth2"
)

type ProviderConfig struct {
	IssuerURL,
	ClientID,
	ClientSecret,
	RedirectURL,
	ProviderName string
	Scopes []string
}

func (cfg ProviderConfig) GetOAuth2Config(endpoint oauth2.Endpoint) oauth2.Config {
	return oauth2.Config{
		ClientID:     cfg.ClientID,
		ClientSecret: cfg.ClientSecret,
		RedirectURL:  cfg.RedirectURL,
		Endpoint:     endpoint,
		Scopes:       cfg.Scopes,
	}
}

func (cfg ProviderConfig) GetOIDCConfig() *oidc.Config {
	return &oidc.Config{ClientID: cfg.ClientID}
}

// Provider wires one OIDC provider (e.g. Authentik, Zitadel, Auth0) to the three
// stateful interfaces above. Safe for concurrent use after construction.
type Provider struct {
	name      string // stored on the user record, e.g. "authentik"
	verifier  *oidc.IDTokenVerifier
	oauth2Cfg oauth2.Config
}

func NewProvider(
	ctx context.Context,
	cfg ProviderConfig,
) (*Provider, error) {
	p, err := oidc.NewProvider(ctx, cfg.IssuerURL)
	if err != nil {
		return nil, fmt.Errorf("oidc discovery %q: %w", cfg.IssuerURL, err)
	}
	return &Provider{
		// go-oidc Verify() checks: signature (JWKS + rotation), iss, aud, exp, iat.
		verifier:  p.Verifier(cfg.GetOIDCConfig()),
		oauth2Cfg: cfg.GetOAuth2Config(p.Endpoint()),
		name:      cfg.ProviderName,
	}, nil
}

// The methods below implement [ProviderInterface].

func (p *Provider) Exchange(ctx context.Context, code string, opts ...oauth2.AuthCodeOption) (*oauth2.Token, error) {
	return p.oauth2Cfg.Exchange(ctx, code, opts...)
}

func (p *Provider) Verify(ctx context.Context, rawIDToken string) (*oidc.IDToken, error) {
	return p.verifier.Verify(ctx, rawIDToken)
}

func (p *Provider) AuthCodeURL(state string, opts ...oauth2.AuthCodeOption) string {
	return p.oauth2Cfg.AuthCodeURL(state, opts...)
}

func (p *Provider) Name() string {
	return p.name
}
