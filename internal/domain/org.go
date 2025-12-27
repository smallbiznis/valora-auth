package domain

import "time"

// Domain represents the mapping of a host name to an org.
type Domain struct {
	ID                   int64
	Host                 string
	OrgID                int64
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

// Org represents a logical organization.
type Org struct {
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

// Branding holds white-label information for an org.
type Branding struct {
	OrgID            int64
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

// AuthProvider represents an enabled authentication option for an org.
type AuthProvider struct {
	ID               int64
	OrgID            int64
	ProviderType     string
	ProviderConfigID *int64
	IsActive         bool
	CreatedAt        time.Time
	UpdatedAt        time.Time
}

// PasswordConfig controls password login policy per org.
type PasswordConfig struct {
	OrgID                  int64
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
}

// OTPConfig holds OTP login policy per org.
type OTPConfig struct {
	OrgID         int64
	Channel       string
	Provider      string
	APIKey        string
	Sender        string
	Template      string
	ExpirySeconds int
	CreatedAt     time.Time
	UpdatedAt     time.Time
}

// OAuthIDPConfig stores social login configuration.
type OAuthIDPConfig struct {
	OrgID            int64
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
}

// OAuthClient represents an OAuth2/OIDC client registration.
type OAuthClient struct {
	ID                       int64
	OrgID                    int64
	AppID                    *int64
	ClientID                 string
	ClientSecret             string
	RedirectURIs             []string
	Grants                   []string
	Scopes                   []string
	TokenEndpointAuthMethods []string
	RequireConsent           bool
	CreatedAt                time.Time
}
