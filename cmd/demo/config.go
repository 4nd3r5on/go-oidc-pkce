package main

import (
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	oidcpkce "github.com/4nd3r5on/go-oidc-pkce"
)

type config struct {
	// OIDC provider
	IssuerURL    string // OIDC_ISSUER_URL   (required) e.g. https://accounts.google.com
	ClientID     string // OIDC_CLIENT_ID    (required)
	ClientSecret string // OIDC_CLIENT_SECRET (required)
	ProviderName string // OIDC_PROVIDER_NAME (optional, default "oidc")

	// Server
	Addr        string        // DEMO_ADDR       (optional, default ":8080")
	ExternalURL string        // DEMO_EXTERNAL_URL (required) e.g. http://localhost:8080
	SessionTTL  time.Duration // DEMO_SESSION_TTL  (optional, default 24h)
}

func loadConfig() (config, error) {
	cfg := config{
		ProviderName: envOr("OIDC_PROVIDER_NAME", "oidc"),
		Addr:         envOr("DEMO_ADDR", ":8080"),
		SessionTTL:   24 * time.Hour,
	}

	cfg.IssuerURL = os.Getenv("OIDC_ISSUER_URL")
	cfg.ClientID = os.Getenv("OIDC_CLIENT_ID")
	cfg.ClientSecret = os.Getenv("OIDC_CLIENT_SECRET")
	cfg.ExternalURL = os.Getenv("DEMO_EXTERNAL_URL")

	if raw := os.Getenv("DEMO_SESSION_TTL"); raw != "" {
		d, err := time.ParseDuration(raw)
		if err != nil {
			return config{}, fmt.Errorf("DEMO_SESSION_TTL: %w", err)
		}
		cfg.SessionTTL = d
	}

	var missing []string
	for _, pair := range [][2]string{
		{"OIDC_ISSUER_URL", cfg.IssuerURL},
		{"OIDC_CLIENT_ID", cfg.ClientID},
		{"OIDC_CLIENT_SECRET", cfg.ClientSecret},
		{"DEMO_EXTERNAL_URL", cfg.ExternalURL},
	} {
		if pair[1] == "" {
			missing = append(missing, pair[0])
		}
	}
	if len(missing) > 0 {
		return config{}, errors.New("missing required env vars: " + strings.Join(missing, ", "))
	}

	return cfg, nil
}

func (c config) providerConfig() oidcpkce.ProviderConfig {
	return oidcpkce.ProviderConfig{
		IssuerURL:    c.IssuerURL,
		ClientID:     c.ClientID,
		ClientSecret: c.ClientSecret,
		RedirectURL:  c.ExternalURL + "/auth/callback",
		ProviderName: c.ProviderName,
		Scopes:       []string{"openid", "email", "profile"},
	}
}

func envOr(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}
