// Package google signs people in with their Google account.
//
// Hand-rolled over net/http, like the GitHub driver and for the same reason:
// the dance is one redirect and one POST, and the access token is used once
// and discarded.
package google

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/lemmego/auth"
)

const (
	authorizeURL = "https://accounts.google.com/o/oauth2/v2/auth"
	tokenURL     = "https://oauth2.googleapis.com/token"
	userinfoURL  = "https://openidconnect.googleapis.com/v1/userinfo"
)

// Name is what appears in a URL: /auth/google.
const Name = "google"

// Scopes requested. openid is what makes this OpenID Connect rather than
// bare OAuth, and email is what carries the verified flag.
const scopes = "openid email profile"

// Provider is the Google driver.
type Provider struct {
	clientID     string
	clientSecret string
	client       *http.Client

	authorizeURL string
	tokenURL     string
	userinfoURL  string
}

// Option configures a Provider.
type Option func(*Provider)

// WithHTTPClient replaces the client.
func WithHTTPClient(client *http.Client) Option {
	return func(p *Provider) { p.client = client }
}

// New returns the driver.
func New(clientID, clientSecret string, opts ...Option) (*Provider, error) {
	if clientID == "" || clientSecret == "" {
		return nil, errors.New("google: a client id and secret are required")
	}
	p := &Provider{
		clientID:     clientID,
		clientSecret: clientSecret,
		client:       &http.Client{Timeout: 10 * time.Second},
		authorizeURL: authorizeURL,
		tokenURL:     tokenURL,
		userinfoURL:  userinfoURL,
	}
	for _, opt := range opts {
		opt(p)
	}
	return p, nil
}

var _ auth.SocialProvider = (*Provider)(nil)

func (p *Provider) Name() string { return Name }

// AuthorizeURL is where to send somebody.
func (p *Provider) AuthorizeURL(state, redirectURI string) (string, error) {
	if state == "" {
		return "", errors.New("google: AuthorizeURL needs a state bound to the session")
	}
	if redirectURI == "" {
		return "", errors.New("google: AuthorizeURL needs a redirect URI")
	}

	query := url.Values{}
	query.Set("client_id", p.clientID)
	query.Set("redirect_uri", redirectURI)
	query.Set("response_type", "code")
	query.Set("scope", scopes)
	query.Set("state", state)
	// No refresh token is asked for, because nothing here uses one: this
	// flow signs somebody in and wants nothing further from Google. A
	// refresh token would be a long-lived credential to somebody else's
	// account held for no purpose.
	query.Set("access_type", "online")
	// select_account rather than none, so somebody on a shared machine is
	// shown which account they are about to use rather than being signed in
	// as whoever Google remembers.
	query.Set("prompt", "select_account")

	return p.authorizeURL + "?" + query.Encode(), nil
}

// Identity exchanges the code for who Google says this is.
func (p *Provider) Identity(ctx context.Context, code, redirectURI string) (*auth.SocialIdentity, error) {
	if code == "" {
		return nil, errors.New("google: the callback carried no code")
	}

	token, err := p.exchange(ctx, code, redirectURI)
	if err != nil {
		return nil, err
	}

	profile, err := p.userinfo(ctx, token)
	if err != nil {
		return nil, err
	}

	identity := &auth.SocialIdentity{
		Provider: Name,
		// The OpenID subject. Stable for the life of the account, and
		// deliberately not the email — a Google Workspace address can be
		// reassigned to a new person when somebody leaves, and a link that
		// followed the email would follow it to them.
		Subject:       profile.Subject,
		Email:         strings.ToLower(profile.Email),
		EmailVerified: profile.EmailVerified,
		Name:          profile.Name,
		AvatarURL:     profile.Picture,
	}
	// Google has no handle, so none is suggested. The application picks one,
	// which it has to do anyway for the cases where GitHub's is taken.
	return identity, nil
}

func (p *Provider) exchange(ctx context.Context, code, redirectURI string) (string, error) {
	form := url.Values{}
	form.Set("client_id", p.clientID)
	form.Set("client_secret", p.clientSecret)
	form.Set("code", code)
	form.Set("redirect_uri", redirectURI)
	form.Set("grant_type", "authorization_code")

	request, err := http.NewRequestWithContext(ctx, http.MethodPost,
		p.tokenURL, strings.NewReader(form.Encode()))
	if err != nil {
		return "", err
	}
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	request.Header.Set("Accept", "application/json")

	var out struct {
		AccessToken      string `json:"access_token"`
		IDToken          string `json:"id_token"`
		Error            string `json:"error"`
		ErrorDescription string `json:"error_description"`
	}
	if err := p.do(request, &out); err != nil {
		return "", err
	}
	if out.Error != "" {
		return "", fmt.Errorf("google: the exchange was refused: %s (%s)",
			out.Error, out.ErrorDescription)
	}
	if out.AccessToken == "" {
		return "", errors.New("google: the exchange returned no token")
	}

	// The id_token is deliberately ignored.
	//
	// Verifying it means fetching and caching Google's signing keys and
	// checking an audience, an issuer and an expiry — four more things to get
	// wrong. Calling userinfo with the access token this exchange just
	// returned over TLS from Google's own token endpoint establishes the same
	// facts through a channel that is already authenticated, and the token
	// is discarded immediately afterwards.
	return out.AccessToken, nil
}

type googleProfile struct {
	Subject       string `json:"sub"`
	Email         string `json:"email"`
	EmailVerified bool   `json:"email_verified"`
	Name          string `json:"name"`
	Picture       string `json:"picture"`
}

func (p *Provider) userinfo(ctx context.Context, token string) (*googleProfile, error) {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, p.userinfoURL, nil)
	if err != nil {
		return nil, err
	}
	request.Header.Set("Authorization", "Bearer "+token)
	request.Header.Set("Accept", "application/json")

	var profile googleProfile
	if err := p.do(request, &profile); err != nil {
		return nil, err
	}
	if profile.Subject == "" {
		return nil, errors.New("google: the profile has no subject, so nothing can be keyed on it")
	}
	return &profile, nil
}

func (p *Provider) do(request *http.Request, into any) error {
	response, err := p.client.Do(request)
	if err != nil {
		return fmt.Errorf("google: %w", err)
	}
	defer response.Body.Close()

	body, err := io.ReadAll(io.LimitReader(response.Body, 1<<20))
	if err != nil {
		return fmt.Errorf("google: reading the response: %w", err)
	}
	if response.StatusCode < 200 || response.StatusCode > 299 {
		return fmt.Errorf("google: %s answered %d", request.URL.Path, response.StatusCode)
	}
	if err := json.Unmarshal(body, into); err != nil {
		return fmt.Errorf("google: %s answered something that is not JSON: %w",
			request.URL.Path, err)
	}
	return nil
}
