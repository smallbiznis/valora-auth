package oauth

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	domainoauth "github.com/smallbiznis/valora-auth/internal/domain/oauth"
)

// ProviderClient encapsulates outbound HTTP calls to external IdPs.
type ProviderClient interface {
	ExchangeCode(ctx context.Context, provider domainoauth.OAuthProviderConfig, code, codeVerifier, redirectURI string) (*domainoauth.OAuthTokenResponse, error)
	FetchUserInfo(ctx context.Context, provider domainoauth.OAuthProviderConfig, accessToken string) (*domainoauth.OAuthUserInfo, error)
}

// HTTPProviderClient is the default HTTP implementation.
type HTTPProviderClient struct {
	httpClient *http.Client
}

// NewHTTPProviderClient constructs the default ProviderClient.
func NewHTTPProviderClient(client *http.Client) *HTTPProviderClient {
	if client == nil {
		client = &http.Client{Timeout: 10 * time.Second}
	}
	return &HTTPProviderClient{httpClient: client}
}

// ExchangeCode performs the OAuth token exchange.
func (c *HTTPProviderClient) ExchangeCode(ctx context.Context, provider domainoauth.OAuthProviderConfig, code, codeVerifier, redirectURI string) (*domainoauth.OAuthTokenResponse, error) {
	if strings.TrimSpace(provider.TokenURL) == "" {
		return nil, fmt.Errorf("token url missing")
	}
	data := url.Values{}
	data.Set("grant_type", "authorization_code")
	data.Set("code", code)
	data.Set("redirect_uri", redirectURI)
	data.Set("client_id", provider.ClientID)
	if provider.ClientSecret != "" {
		data.Set("client_secret", provider.ClientSecret)
	}
	if strings.TrimSpace(codeVerifier) != "" {
		data.Set("code_verifier", codeVerifier)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, provider.TokenURL, strings.NewReader(data.Encode()))
	if err != nil {
		return nil, fmt.Errorf("build token request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("token exchange request: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, fmt.Errorf("read token response: %w", err)
	}
	if resp.StatusCode >= 300 {
		return nil, fmt.Errorf("token exchange failed: status=%d", resp.StatusCode)
	}

	var raw map[string]any
	if err := json.Unmarshal(body, &raw); err != nil {
		return nil, fmt.Errorf("decode token response: %w", err)
	}

	token := &domainoauth.OAuthTokenResponse{
		AccessToken:  stringValue(raw["access_token"]),
		RefreshToken: stringValue(raw["refresh_token"]),
		TokenType:    stringValue(raw["token_type"]),
		IDToken:      stringValue(raw["id_token"]),
		Scope:        stringValue(raw["scope"]),
		Raw:          raw,
	}
	if exp := raw["expires_in"]; exp != nil {
		token.ExpiresIn = int64Value(exp)
	}
	return token, nil
}

// FetchUserInfo loads the userinfo endpoint profile.
func (c *HTTPProviderClient) FetchUserInfo(ctx context.Context, provider domainoauth.OAuthProviderConfig, accessToken string) (*domainoauth.OAuthUserInfo, error) {
	if strings.TrimSpace(provider.UserInfoURL) == "" {
		return nil, fmt.Errorf("userinfo url missing")
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, provider.UserInfoURL, nil)
	if err != nil {
		return nil, fmt.Errorf("build userinfo request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+accessToken)
	req.Header.Set("Accept", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("userinfo request: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, fmt.Errorf("read userinfo: %w", err)
	}
	if resp.StatusCode >= 300 {
		return nil, fmt.Errorf("userinfo failed: status=%d", resp.StatusCode)
	}

	var raw map[string]any
	if err := json.Unmarshal(body, &raw); err != nil {
		return nil, fmt.Errorf("decode userinfo: %w", err)
	}

	return &domainoauth.OAuthUserInfo{
		Subject: stringValue(raw["sub"]),
		Email:   stringValue(coalesce(raw["email"], raw["mail"])),
		Name:    stringValue(coalesce(raw["name"], raw["displayName"])),
		Picture: stringValue(coalesce(raw["picture"], raw["avatar_url"])),
	}, nil
}

func stringValue(input any) string {
	switch v := input.(type) {
	case string:
		return v
	case fmt.Stringer:
		return v.String()
	case json.Number:
		return v.String()
	default:
		return ""
	}
}

func int64Value(input any) int64 {
	switch v := input.(type) {
	case float64:
		return int64(v)
	case float32:
		return int64(v)
	case int64:
		return v
	case int32:
		return int64(v)
	case json.Number:
		n, _ := v.Int64()
		return n
	case string:
		if n, err := strconv.ParseInt(v, 10, 64); err == nil {
			return n
		}
	}
	return 0
}

func coalesce(values ...any) any {
	for _, v := range values {
		switch val := v.(type) {
		case string:
			if strings.TrimSpace(val) != "" {
				return v
			}
		case nil:
			continue
		default:
			return v
		}
	}
	return nil
}
