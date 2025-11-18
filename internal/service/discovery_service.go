package service

import (
	"fmt"

	"github.com/smallbiznis/smallbiznis-auth/internal/tenant"
)

// DiscoveryService builds responses for discovery endpoints.
type DiscoveryService struct{}

// TenantDiscoveryResponse matches Auth0 tenant discovery output.
type TenantDiscoveryResponse struct {
	Tenant    string            `json:"tenant"`
	Branding  map[string]string `json:"branding"`
	Providers []map[string]any  `json:"providers"`
}

// OpenIDConfiguration matches OIDC discovery document.
type OpenIDConfiguration struct {
	Issuer                           string   `json:"issuer"`
	AuthorizationEndpoint            string   `json:"authorization_endpoint"`
	TokenEndpoint                    string   `json:"token_endpoint"`
	UserinfoEndpoint                 string   `json:"userinfo_endpoint"`
	JWKSURI                          string   `json:"jwks_uri"`
	ResponseTypesSupported           []string `json:"response_types_supported"`
	SubjectTypesSupported            []string `json:"subject_types_supported"`
	IDTokenSigningAlgValuesSupported []string `json:"id_token_signing_alg_values_supported"`
	ScopesSupported                  []string `json:"scopes_supported"`
	TokenEndpointAuthMethods         []string `json:"token_endpoint_auth_methods_supported"`
	ClaimsSupported                  []string `json:"claims_supported"`
}

// TenantMetadata builds tenant discovery payload.
func (s *DiscoveryService) TenantMetadata(ctx *tenant.Context) TenantDiscoveryResponse {
	branding := map[string]string{
		"logo_url":      *ctx.Branding.LogoURL,
		"primary_color": *ctx.Branding.PrimaryColor,
	}
	providers := make([]map[string]any, 0, len(ctx.AuthProviders))
	for _, provider := range ctx.AuthProviders {
		providers = append(providers, map[string]any{
			"type":    provider.ProviderType,
			"name":    provider.ProviderType,
			"enabled": provider.IsActive,
		})
	}
	return TenantDiscoveryResponse{
		Tenant:    ctx.Tenant.Name,
		Branding:  branding,
		Providers: providers,
	}
}

// OpenIDConfigurationResponse builds the OIDC document using request host.
func (s *DiscoveryService) OpenIDConfigurationResponse(host string, ctx *tenant.Context) OpenIDConfiguration {
	issuer := fmt.Sprintf("https://%s", host)
	base := issuer
	authorize := fmt.Sprintf("%s/oauth/authorize", base)
	token := fmt.Sprintf("%s/oauth/token", base)
	userinfo := fmt.Sprintf("%s/userinfo", base)
	jwks := fmt.Sprintf("%s/.well-known/jwks.json", base)
	return OpenIDConfiguration{
		Issuer:                           issuer,
		AuthorizationEndpoint:            authorize,
		TokenEndpoint:                    token,
		UserinfoEndpoint:                 userinfo,
		JWKSURI:                          jwks,
		ResponseTypesSupported:           []string{"code", "token"},
		SubjectTypesSupported:            []string{"public"},
		IDTokenSigningAlgValuesSupported: []string{"HS256"},
		ScopesSupported:                  []string{"openid", "profile", "email", "offline_access"},
		TokenEndpointAuthMethods:         []string{"client_secret_post"},
		ClaimsSupported:                  []string{"sub", "email", "name", "picture", "tenant_id"},
	}
}
