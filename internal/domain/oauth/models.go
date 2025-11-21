package oauth

import "time"

// OAuthProvider represents an enabled OAuth/OIDC provider that tenants expose.
type OAuthProvider struct {
	Name        string
	DisplayName string
	IconURL     string
	AuthURL     string
	TenantID    int64
}

// OAuthProviderConfig stores the persisted configuration for an external IdP.
type OAuthProviderConfig struct {
	TenantID     int64
	ProviderName string
	DisplayName  string
	IconURL      string
	ClientID     string
	ClientSecret string
	AuthURL      string
	TokenURL     string
	UserInfoURL  string
	Scopes       []string
	Extra        map[string]any
	CreatedAt    time.Time
	UpdatedAt    time.Time
}

// OAuthState captures the state/nonce/pkce tuple persisted during authorization.
type OAuthState struct {
	State        string
	Nonce        string
	CodeVerifier string
	Provider     string
	RedirectURI  string
	TenantID     int64
	CreatedAt    time.Time
}

// OAuthTokenResponse models the response from an external IdP token endpoint.
type OAuthTokenResponse struct {
	AccessToken  string
	RefreshToken string
	ExpiresIn    int64
	TokenType    string
	IDToken      string
	Scope        string
	Raw          map[string]any
}

// OAuthUserInfo represents the normalized profile data returned by IdPs.
type OAuthUserInfo struct {
	Subject string
	Email   string
	Name    string
	Picture string
}
