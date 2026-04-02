package oidcpkce

// LoginState is the per-flow bundle persisted across the browser round-trip.
// All fields except RedirectURI are single-use and must be invalidated after the callback.
type LoginState struct {
	State        string // CSRF guard; verified on callback
	Nonce        string // replay guard; verified inside ID token claims
	CodeVerifier string // PKCE; sent at token exchange, verified by provider
	RedirectURI  string // optional pre-login destination
}

// DefaultClaims are the normalised fields extracted from a verified ID token.
type DefaultClaims struct {
	Sub           string `json:"sub"` // stable identity key
	Email         string `json:"email"`
	EmailVerified bool   `json:"email_verified"`
	Name          string `json:"name"`
	Nonce         string `json:"nonce"`
}

func (c DefaultClaims) GetNonce() string {
	return c.Nonce
}
