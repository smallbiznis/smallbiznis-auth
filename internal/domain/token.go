package domain

import "time"

// OAuthToken persists refresh tokens.
type OAuthToken struct {
	ID            int64
	TenantID      int64
	UserID        int64
	ClientID      string
	AccessToken   string
	Scope         string
	Scopes        []string
	RefreshToken  string
	AccessTokenID string
	CreatedAt     time.Time
	ExpiresAt     time.Time
	RotatedAt     time.Time
	Revoked       bool
}

// OAuthCode models short-lived authorization codes.
type OAuthCode struct {
	Code                string
	TenantID            int64
	UserID              int64
	ClientID            string
	RedirectURI         string
	Scope               string
	CodeChallenge       string
	CodeChallengeMethod string
	ExpiresAt           time.Time
	Revoked             bool
	CreatedAt           time.Time
	Used                bool
}

// OAuthKey stores per-tenant signing keys.
type OAuthKey struct {
	ID        int64
	TenantID  int64
	KID       string
	Secret    []byte
	Algorithm string
	Active    bool
	CreatedAt time.Time
	RotatedAt *time.Time
}
