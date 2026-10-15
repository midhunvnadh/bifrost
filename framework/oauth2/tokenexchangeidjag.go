package oauth2

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"slices"
	"strings"
	"time"

	"github.com/maximhq/bifrost/core/schemas"
	"github.com/maximhq/bifrost/framework/configstore/tables"
)

// Wire values for the Cross App Access (ID-JAG) profile of token exchange.
const (
	requestedTokenTypeIDJAG = "urn:ietf:params:oauth:token-type:id-jag"
	// resourceEndpointTTL bounds how long a discovered upstream token endpoint
	// is reused before discovery runs again.
	resourceEndpointTTL = time.Hour
)

// resourceEndpoint is a cached leg-2 token endpoint for one MCP client URL.
type resourceEndpoint struct {
	upstreamURL string
	endpoint    string
	fetchedAt   time.Time
}

// getIDJAGAccessToken is GetExchangedAccessToken for the id_jag profile. The
// user's ID or refresh token (never the inbound access token) is exchanged for
// an ID-JAG, which the upstream authorization server redeems for its own token.
// Only user identities qualify: the subject must name a person. The cache is
// keyed by user and client, so a hit skips loading the stored subject.
func (p *OAuth2Provider) getIDJAGAccessToken(ctx *schemas.BifrostContext, config *schemas.MCPClientConfig) (string, error) {
	if ctx.MCPAuthMode() != schemas.MCPAuthModeUser {
		return "", schemas.ErrExchangeSubjectTokenMissing
	}
	identity := ctx.MCPIdentity(schemas.MCPAuthModeUser)
	if identity == "" {
		return "", schemas.ErrExchangeSubjectTokenMissing
	}
	key := userTokenCacheKey(schemas.MCPAuthModeUser, identity, config.ID, schemas.TokenExchangeProfileIDJAG)
	if cached, ok := p.userTokens.Get(key); ok {
		return cached.accessToken, nil
	}
	filled, err := p.userTokens.Fill(ctx, key, func() (cachedUserToken, error) {
		subject, err := p.idjagSubject(ctx, identity)
		if err != nil {
			return cachedUserToken{}, err
		}
		response, err := p.performIDJAGExchange(ctx, config, subject)
		if err != nil {
			return cachedUserToken{}, err
		}
		return cachedTokenFromResponse(response), nil
	})
	if err != nil {
		return "", err
	}
	return filled.accessToken, nil
}

// idjagSubject loads the user's ID-JAG subject from their stored SSO session
// through the identity-provider resolver.
func (p *OAuth2Provider) idjagSubject(ctx context.Context, userID string) (*schemas.IDJAGSubjectToken, error) {
	if userID == "" {
		return nil, schemas.ErrExchangeSubjectTokenMissing
	}
	resolver, ok := p.tokenExchangeIdPResolver().(schemas.IDJAGSubjectResolver)
	if !ok {
		return nil, schemas.ErrExchangeSubjectTokenMissing
	}
	subject, err := resolver.IDJAGSubjectForUser(ctx, userID)
	if err != nil {
		return nil, err
	}
	if subject == nil || subject.Token == "" {
		return nil, schemas.ErrExchangeSubjectTokenMissing
	}
	return subject, nil
}

// performIDJAGExchange runs both legs: the identity provider issues an ID-JAG
// for the configured audience (leg 1), then the upstream authorization server
// exchanges it with the jwt-bearer grant (leg 2). The ID-JAG is used once and
// never cached or logged.
func (p *OAuth2Provider) performIDJAGExchange(ctx context.Context, config *schemas.MCPClientConfig, subject *schemas.IDJAGSubjectToken) (*schemas.OAuth2TokenExchangeResponse, error) {
	cfg := config.TokenExchange
	assertion, err := p.rawExchange(ctx, config, func(idp *schemas.TokenExchangeIdP) (url.Values, error) {
		return buildIDJAGRequestForm(idp, config, subject)
	})
	if err != nil {
		return nil, err
	}
	if assertion.IssuedTokenType != "" && assertion.IssuedTokenType != requestedTokenTypeIDJAG {
		return nil, fmt.Errorf("identity provider issued %q instead of an ID-JAG for MCP client %s", assertion.IssuedTokenType, config.Name)
	}
	if strings.TrimSpace(assertion.AccessToken) == "" {
		return nil, fmt.Errorf("identity provider returned an empty ID-JAG for MCP client %s", config.Name)
	}

	ctx = withRequirePublicTarget(ctx, config.RequirePublicTarget)
	endpoint, err := p.resourceTokenEndpoint(ctx, config)
	if err != nil {
		return nil, err
	}
	form := url.Values{}
	form.Set("grant_type", grantTypeJWTBearer)
	form.Set("assertion", assertion.AccessToken)
	form.Set("client_id", strings.TrimSpace(cfg.ResourceClientID.GetValue()))
	if secret := strings.TrimSpace(cfg.ResourceClientSecret.GetValue()); secret != "" {
		form.Set("client_secret", secret)
	}
	response, err := p.callTokenEndpoint(ctx, endpoint, form)
	if err != nil {
		var permanent *PermanentOAuthError
		if errors.As(err, &permanent) {
			return nil, &schemas.TokenExchangeRejectedError{Detail: "upstream authorization server: " + sanitizeTokenExchangeRejection(permanent.Body)}
		}
		return nil, fmt.Errorf("ID-JAG redemption for MCP client %s failed: %w", config.Name, err)
	}
	return response, nil
}

// buildIDJAGRequestForm builds the leg-1 RFC 8693 request asking the identity
// provider for an ID-JAG. Client credentials follow the same rules as the
// direct profile; identity providers accept the subject only from the
// application it was issued to, so use_idp_credentials is the usual setting.
func buildIDJAGRequestForm(idp *schemas.TokenExchangeIdP, config *schemas.MCPClientConfig, subject *schemas.IDJAGSubjectToken) (url.Values, error) {
	cfg := config.TokenExchange
	clientID, clientSecret, err := exchangeClientCredentials(idp, cfg)
	if err != nil {
		return nil, err
	}
	data := url.Values{}
	data.Set("grant_type", grantTypeTokenExchange)
	data.Set("requested_token_type", requestedTokenTypeIDJAG)
	data.Set("subject_token", subject.Token)
	data.Set("subject_token_type", subject.TokenType)
	data.Set("audience", cfg.Audience)
	// resource is sent only when configured: Okta answers invalid_target when
	// the agent's connection defines no resource indicator, which is the default.
	if resource := strings.TrimSpace(cfg.Resource); resource != "" {
		data.Set("resource", resource)
	}
	if scope := scopeParam(cfg, false); scope != "" {
		data.Set("scope", scope)
	}
	data.Set("client_id", clientID)
	if clientSecret != "" {
		data.Set("client_secret", clientSecret)
	}
	return data, nil
}

// resourceTokenEndpoint returns the upstream authorization server's token
// endpoint: the configured override, or one discovered from the MCP server's
// protected resource metadata. Discovery must show the server accepts the
// jwt-bearer grant, otherwise it cannot redeem an ID-JAG.
func (p *OAuth2Provider) resourceTokenEndpoint(ctx context.Context, config *schemas.MCPClientConfig) (string, error) {
	if override := config.TokenExchange.ResourceTokenEndpointURL(); override != "" {
		return override, nil
	}
	upstreamURL := ""
	if config.ConnectionString != nil {
		upstreamURL = strings.TrimSpace(config.ConnectionString.GetValue())
	}
	if upstreamURL == "" {
		return "", fmt.Errorf("MCP client %s has no URL to discover its authorization server from; set token_exchange.resource_token_endpoint", config.Name)
	}
	if v, ok := p.resourceEndpoints.Load(config.ID); ok {
		cached := v.(resourceEndpoint)
		if cached.upstreamURL == upstreamURL && time.Since(cached.fetchedAt) < resourceEndpointTTL {
			return cached.endpoint, nil
		}
	}
	metadata, err := DiscoverOAuthMetadata(ctx, upstreamURL)
	if err != nil {
		return "", fmt.Errorf("discover authorization server for MCP client %s: %w", config.Name, err)
	}
	if metadata.TokenURL == "" {
		return "", fmt.Errorf("authorization server for MCP client %s publishes no token endpoint", config.Name)
	}
	if len(metadata.GrantTypes) > 0 && !slices.Contains(metadata.GrantTypes, grantTypeJWTBearer) {
		return "", fmt.Errorf("authorization server for MCP client %s does not support the jwt-bearer grant needed to redeem an ID-JAG", config.Name)
	}
	p.resourceEndpoints.Store(config.ID, resourceEndpoint{upstreamURL: upstreamURL, endpoint: metadata.TokenURL, fetchedAt: time.Now()})
	return metadata.TokenURL, nil
}

// exchangeIDJAGAdminCredential runs the id_jag exchange for the signed-in admin.
// When the subject is a refresh token it is returned as the response's
// refresh token, so the retained admin credential can be renewed by running
// both legs again (see refreshIDJAGAdminToken).
func (p *OAuth2Provider) exchangeIDJAGAdminCredential(ctx context.Context, config *schemas.MCPClientConfig) (*schemas.OAuth2TokenExchangeResponse, error) {
	userID, _ := ctx.Value(schemas.BifrostContextKeyUserID).(string)
	subject, err := p.idjagSubject(ctx, userID)
	if err != nil {
		return nil, err
	}
	response, err := p.performIDJAGExchange(ctx, config, subject)
	if err != nil {
		return nil, err
	}
	response.RefreshToken = ""
	if subject.TokenType == schemas.TokenTypeRefreshToken {
		response.RefreshToken = subject.Token
	}
	return response, nil
}

// refreshIDJAGAdminToken renews an id_jag admin credential by exchanging the
// retained identity-provider refresh token for a fresh ID-JAG and upstream
// token. Without a retained refresh token, or when either side refuses, the
// row needs re-verification.
func (p *OAuth2Provider) refreshIDJAGAdminToken(ctx context.Context, token *tables.TableMCPOauthToken, clientConfig *schemas.MCPClientConfig) error {
	if strings.TrimSpace(token.RefreshToken) == "" {
		return p.markExchangeAdminNeedsReauth(token, fmt.Errorf("admin ID-JAG credential has no identity-provider refresh token to renew with"))
	}
	subject := &schemas.IDJAGSubjectToken{Token: token.RefreshToken, TokenType: schemas.TokenTypeRefreshToken}
	response, err := p.performIDJAGExchange(ctx, clientConfig, subject)
	if err != nil {
		var rejected *schemas.TokenExchangeRejectedError
		if errors.As(err, &rejected) {
			return p.markExchangeAdminNeedsReauth(token, err)
		}
		return fmt.Errorf("admin ID-JAG credential renewal failed: %w", err)
	}
	now := time.Now()
	token.AccessToken = strings.TrimSpace(response.AccessToken)
	token.ExpiresAt = nil
	if response.ExpiresIn > 0 {
		exp := now.Add(time.Duration(response.ExpiresIn) * time.Second)
		token.ExpiresAt = &exp
	}
	token.LastRefreshedAt = &now
	token.StatusReason = ""
	if err := p.configStore.UpdateOauthToken(ctx, token); err != nil {
		return fmt.Errorf("failed to update admin ID-JAG credential: %w", err)
	}
	p.EvictUserTokenByID(token.ID)
	return nil
}

// cachedTokenFromResponse shapes a token response into a cache entry with the
// expiry safety margin applied.
func cachedTokenFromResponse(response *schemas.OAuth2TokenExchangeResponse) cachedUserToken {
	ttl := defaultExchangedTokenTTL
	if response.ExpiresIn > 0 {
		ttl = time.Duration(response.ExpiresIn) * time.Second
	}
	if margined := ttl - exchangeExpirySafetyMargin; margined > 0 {
		ttl = margined
	}
	expiresAt := time.Now().Add(ttl)
	return cachedUserToken{accessToken: response.AccessToken, expiresAt: &expiresAt}
}
