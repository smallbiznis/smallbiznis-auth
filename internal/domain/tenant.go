package domain

import "time"

// Domain represents the mapping of a host name to a tenant.
type Domain struct {
	ID                   int64
	Host                 string
	TenantID             int64
	IsPrimary            bool
	VerificationMethod   string
	VerificationCode     string
	Verified             bool
	VerifiedAt           *time.Time
	CertificateStatus    string
	CertificateUpdatedAt *time.Time
	ProvisioningStatus   string
	ProvisionedAt        *time.Time
	CreatedAt            time.Time
	UpdatedAt            time.Time
}

// Tenant represents a logical tenant/customer.
type Tenant struct {
	ID          int64
	Type        string
	Name        string
	Code        string
	Slug        string
	CountryCode string
	Timezone    string
	IsDefault   bool
	Status      string
	CreatedAt   time.Time
	UpdatedAt   time.Time
}

// Branding holds white-label information for a tenant.
type Branding struct {
	TenantID         int64
	LogoURL          *string
	FaviconURL       *string
	PrimaryColor     *string
	SecondaryColor   *string
	AccentColor      *string
	BackgroundColor  *string
	TextColor        *string
	DarkMode         bool
	CustomCSS        *string
	CustomJS         *string
	CustomHTMLHeader *string
	CustomHTMLFooter *string
	CreatedAt        time.Time
	UpdatedAt        time.Time
}

// AuthProvider represents an enabled authentication option for tenant.
type AuthProvider struct {
	ID               int64
	TenantID         int64
	ProviderType     string
	ProviderConfigID *int64
	IsActive         bool
	CreatedAt        time.Time
	UpdatedAt        time.Time
	// Legacy fields kept for compatibility with existing service code.
	Type    string
	Name    string
	Enabled bool
}

// PasswordConfig controls password login policy per tenant.
type PasswordConfig struct {
	TenantID               int64
	MinLength              int
	RequireUppercase       bool
	RequireNumber          bool
	RequireSymbol          bool
	AllowSignup            bool
	AllowPasswordReset     bool
	LockoutAttempts        int
	LockoutDurationSeconds int
	CreatedAt              time.Time
	UpdatedAt              time.Time
	// Legacy fields retained for compatibility.
	Enabled         bool
	MaxAttempts     int
	LockoutInterval time.Duration
}

// OTPConfig holds OTP login policy per tenant.
type OTPConfig struct {
	TenantID      int64
	Channel       string
	Provider      string
	APIKey        string
	Sender        string
	Template      string
	ExpirySeconds int
	CreatedAt     time.Time
	UpdatedAt     time.Time
	// Backward compatible fields used by the current service flows.
	Enabled bool
	Length  int
	Ttl     time.Duration
}

// OAuthIDPConfig stores social login configuration.
type OAuthIDPConfig struct {
	TenantID         int64
	Provider         string
	ClientID         string
	ClientSecret     string
	IssuerURL        string
	AuthorizationURL string
	TokenURL         string
	UserinfoURL      string
	JWKSURL          string
	Scopes           []string
	Extra            map[string]any
	CreatedAt        time.Time
	UpdatedAt        time.Time
	// Legacy fields retained for compatibility with existing consumers.
	RedirectURI   string
	Enabled       bool
	DisplayName   string
	Authorization string
}
