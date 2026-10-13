// Package github signs people in with their GitHub account.
//
// Hand-rolled over net/http, following pay/stripe's Connect flow: the dance
// is one redirect and one POST, and an OAuth library's value is in the token
// refresh this never needs. The access token is used once, to ask who this
// is, and then discarded.
package github

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/lemmego/auth"
)

// Endpoints, overridable so the flow is testable without a network.
const (
	authorizeURL = "https://github.com/login/oauth/authorize"
	tokenURL     = "https://github.com/login/oauth/access_token"
	apiURL       = "https://api.github.com"
)

// Name is what appears in a URL: /auth/github.
const Name = "github"

// Scopes requested.
//
// user:email is the one that matters, and it is not optional: GET /user
// returns the *public profile* email, which is frequently null and is never
// marked verified. The verified primary address only comes from
// GET /user/emails, and without it every sign-in would arrive with
// EmailVerified false — which under the default link policy means no existing
// account can ever be linked, for a reason nobody could diagnose.
const scopes = "read:user user:email"

// Provider is the GitHub driver.
type Provider struct {
	clientID     string
	clientSecret string
	client       *http.Client

	// Overridden in tests. Unexported, so there is no way to point a
	// production build at somebody else's authorization server.
	authorizeURL string
	tokenURL     string
	apiURL       string
}

// Option configures a Provider.
type Option func(*Provider)

// WithHTTPClient replaces the client, for a timeout or a test server.
func WithHTTPClient(client *http.Client) Option {
	return func(p *Provider) { p.client = client }
}

// New returns the driver.
func New(clientID, clientSecret string, opts ...Option) (*Provider, error) {
	if clientID == "" || clientSecret == "" {
		return nil, errors.New("github: a client id and secret are required")
	}
	p := &Provider{
		clientID:     clientID,
		clientSecret: clientSecret,
		// A timeout, because a provider that stops answering must not hold a
		// request open: the default http.Client has none at all.
		client:       &http.Client{Timeout: 10 * time.Second},
		authorizeURL: authorizeURL,
		tokenURL:     tokenURL,
		apiURL:       apiURL,
	}
	for _, opt := range opts {
		opt(p)
	}
	return p, nil
}

var _ auth.SocialProvider = (*Provider)(nil)

func (p *Provider) Name() string { return Name }

// AuthorizeURL is where to send somebody.
//
// An empty state is refused rather than generated, which is pay/stripe's
// rule and for the same reason: a state this package invented would be bound
// to nothing, which is a CSRF hole wearing the name of its own defence. The
// caller binds it to the session.
func (p *Provider) AuthorizeURL(state, redirectURI string) (string, error) {
	if state == "" {
		return "", errors.New("github: AuthorizeURL needs a state bound to the session")
	}
	if redirectURI == "" {
		return "", errors.New("github: AuthorizeURL needs a redirect URI")
	}

	query := url.Values{}
	query.Set("client_id", p.clientID)
	query.Set("redirect_uri", redirectURI)
	query.Set("scope", scopes)
	query.Set("state", state)
	// Asks GitHub not to reuse an existing authorization silently, so
	// somebody signing in on a shared machine is shown which account they
	// are about to use.
	query.Set("allow_signup", "true")

	return p.authorizeURL + "?" + query.Encode(), nil
}

// Identity exchanges the code for who GitHub says this is.
func (p *Provider) Identity(ctx context.Context, code, redirectURI string) (*auth.SocialIdentity, error) {
	if code == "" {
		return nil, errors.New("github: the callback carried no code")
	}

	token, err := p.exchange(ctx, code, redirectURI)
	if err != nil {
		return nil, err
	}

	profile, err := p.profile(ctx, token)
	if err != nil {
		return nil, err
	}

	identity := &auth.SocialIdentity{
		Provider:  Name,
		Subject:   strconv.FormatInt(profile.ID, 10),
		Name:      profile.Name,
		Handle:    strings.ToLower(profile.Login),
		AvatarURL: profile.AvatarURL,
	}
	if identity.Name == "" {
		identity.Name = profile.Login
	}

	// The verified primary, from the endpoint that actually knows. A failure
	// here is not fatal: somebody can still be signed in and linked by
	// subject, and an identity with no email simply creates an account rather
	// than joining one — which is the safe direction.
	if email, verified, err := p.primaryEmail(ctx, token); err == nil {
		identity.Email = email
		identity.EmailVerified = verified
	} else if profile.Email != "" {
		// The public profile address, and never marked verified, because
		// GitHub does not say that it is. Treating it as verified here is
		// exactly the account takeover the policy exists to prevent.
		identity.Email = profile.Email
		identity.EmailVerified = false
	}

	return identity, nil
}

func (p *Provider) exchange(ctx context.Context, code, redirectURI string) (string, error) {
	form := url.Values{}
	form.Set("client_id", p.clientID)
	form.Set("client_secret", p.clientSecret)
	form.Set("code", code)
	form.Set("redirect_uri", redirectURI)

	request, err := http.NewRequestWithContext(ctx, http.MethodPost,
		p.tokenURL, strings.NewReader(form.Encode()))
	if err != nil {
		return "", err
	}
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	// Without this GitHub answers with a urlencoded body, which is a
	// different parse and a different failure when it changes.
	request.Header.Set("Accept", "application/json")

	var out struct {
		AccessToken      string `json:"access_token"`
		Scope            string `json:"scope"`
		Error            string `json:"error"`
		ErrorDescription string `json:"error_description"`
	}
	if err := p.do(request, &out); err != nil {
		return "", err
	}
	if out.Error != "" {
		return "", fmt.Errorf("github: the exchange was refused: %s (%s)",
			out.Error, out.ErrorDescription)
	}
	if out.AccessToken == "" {
		return "", errors.New("github: the exchange returned no token")
	}

	// The scope that comes back is checked rather than assumed, the way
	// pay/stripe checks its own: an authorization granted before these
	// scopes were set, or a flow started elsewhere, can come back narrower —
	// and a narrower grant means the email lookup below silently returns
	// nothing verified.
	if out.Scope != "" && !strings.Contains(out.Scope, "user:email") {
		return "", fmt.Errorf("github: the authorisation came back with scope "+
			"%q, which cannot read a verified email address", out.Scope)
	}
	return out.AccessToken, nil
}

type githubProfile struct {
	ID        int64  `json:"id"`
	Login     string `json:"login"`
	Name      string `json:"name"`
	Email     string `json:"email"`
	AvatarURL string `json:"avatar_url"`
}

func (p *Provider) profile(ctx context.Context, token string) (*githubProfile, error) {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, p.apiURL+"/user", nil)
	if err != nil {
		return nil, err
	}
	p.authorize(request, token)

	var profile githubProfile
	if err := p.do(request, &profile); err != nil {
		return nil, err
	}
	if profile.ID == 0 {
		return nil, errors.New("github: the profile has no id, so nothing can be keyed on it")
	}
	return &profile, nil
}

// primaryEmail returns the primary address and whether GitHub says it is
// verified.
func (p *Provider) primaryEmail(ctx context.Context, token string) (string, bool, error) {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, p.apiURL+"/user/emails", nil)
	if err != nil {
		return "", false, err
	}
	p.authorize(request, token)

	var addresses []struct {
		Email    string `json:"email"`
		Primary  bool   `json:"primary"`
		Verified bool   `json:"verified"`
	}
	if err := p.do(request, &addresses); err != nil {
		return "", false, err
	}

	// The primary, and only the primary. Taking the first verified address
	// instead would let somebody add an address they do not use as primary
	// and sign in as whoever owns it here.
	for _, address := range addresses {
		if address.Primary {
			return strings.ToLower(address.Email), address.Verified, nil
		}
	}
	return "", false, errors.New("github: no primary email address")
}

func (p *Provider) authorize(request *http.Request, token string) {
	request.Header.Set("Authorization", "Bearer "+token)
	request.Header.Set("Accept", "application/vnd.github+json")
	request.Header.Set("X-GitHub-Api-Version", "2022-11-28")
}

// do performs a request and decodes the body.
func (p *Provider) do(request *http.Request, into any) error {
	response, err := p.client.Do(request)
	if err != nil {
		return fmt.Errorf("github: %w", err)
	}
	defer response.Body.Close()

	// Bounded, because this is somebody else's server and an unbounded read
	// is an unbounded allocation.
	body, err := io.ReadAll(io.LimitReader(response.Body, 1<<20))
	if err != nil {
		return fmt.Errorf("github: reading the response: %w", err)
	}
	if response.StatusCode < 200 || response.StatusCode > 299 {
		return fmt.Errorf("github: %s answered %d", request.URL.Path, response.StatusCode)
	}
	if err := json.Unmarshal(body, into); err != nil {
		return fmt.Errorf("github: %s answered something that is not JSON: %w",
			request.URL.Path, err)
	}
	return nil
}

// WithEndpoints points the driver at other hosts. Test-only: it is in a
// _test file so a production build cannot reach it.
