package auth

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"net/url"

	"github.com/lemmego/api/app"
	"strings"
)

// Signing in with somebody else's provider — "log in with GitHub" — lives
// here rather than in a module of its own.
//
// It is a credential, and this package already owns credentials: the session
// renewal, the JWT, the cookie and LoginAs are all here, and a separate
// module would need every one of them. What it would hold on its own is two
// structs that each make one HTTP call.
//
// Note the asymmetry with lemmego/oauth2, which is the *server* side — this
// application issuing tokens to third parties, in the spirit of Passport.
// This is the client side, and it is the much smaller thing.

// SocialIdentity is who a provider says somebody is.
type SocialIdentity struct {
	// Provider is the driver's name, "github" or "google".
	Provider string

	// Subject is the provider's own stable id for this person.
	//
	// The thing to key on, never the email: an email address can change
	// hands, and at least one provider lets somebody change theirs. A
	// linked account that followed the email would follow it to whoever
	// owns it next.
	Subject string

	Email string

	// EmailVerified is what the provider claims about that address, and it is
	// the field the whole linking policy turns on.
	//
	// An unverified provider email is an account takeover: anybody can put
	// somebody else's address on a throwaway account at most providers, so
	// trusting it to find an existing user hands them that user. See
	// LinkPolicy.
	EmailVerified bool

	Name      string
	AvatarURL string

	// Handle is a suggestion, not a reservation: GitHub has one and Google
	// does not, and the application decides whether it is usable.
	Handle string
}

// Validate reports why an identity cannot be used.
func (i SocialIdentity) Validate() error {
	switch {
	case i.Provider == "":
		return errors.New("auth: the identity names no provider")
	case i.Subject == "":
		return errors.New("auth: the identity has no subject, so nothing can be keyed on it")
	default:
		return nil
	}
}

// SocialProvider is one identity provider.
//
// Two methods, because the flow is two steps and nothing else about a
// provider is this package's business. A driver holds its own client id and
// secret and makes its own HTTP calls, the way pay/stripe's Connect flow
// does — hand-rolled over net/http rather than through an OAuth library,
// because the dance is one redirect and one POST and the library's value is
// in the token refresh this never needs.
type SocialProvider interface {
	// Name is what appears in a URL: /auth/{name}.
	Name() string

	// AuthorizeURL is where to send somebody.
	//
	// state must be bound to the session that started the flow, and a driver
	// must refuse an empty one rather than inventing a value — a state the
	// driver made up is bound to nothing, which is a CSRF hole wearing the
	// name of its own defence. This package generates and stores it; see
	// StartSocial.
	AuthorizeURL(state, redirectURI string) (string, error)

	// Identity exchanges the code a provider sent back for who it says this
	// person is.
	//
	// The access token is deliberately not returned. This flow signs
	// somebody in and wants nothing else from the provider, so holding a
	// token would be holding a credential to somebody else's service for no
	// reason — and a credential nobody needs is one that can only leak.
	Identity(ctx context.Context, code, redirectURI string) (*SocialIdentity, error)
}

// LinkPolicy decides what happens when a provider returns an email that
// already belongs to an account.
type LinkPolicy int

const (
	// LinkVerifiedOnly links when the provider says the address is verified
	// and the existing account's own address is confirmed. Anything else is
	// refused with ErrLinkRefused, and the person is told to sign in and
	// link it from their settings.
	//
	// The default, and the only one of the three that is safe by itself. The
	// two conditions close different holes: an unverified provider address
	// lets anybody claim somebody else's account by putting their email on a
	// throwaway, and an unconfirmed local address means this application
	// never proved the account's owner reads that inbox either.
	LinkVerifiedOnly LinkPolicy = iota

	// LinkNever refuses every automatic link. An identity is only ever
	// attached from settings, by somebody already signed in.
	//
	// Stricter, and it costs a returning person who forgot they had a
	// password a trip through the reset flow.
	LinkNever

	// LinkAlways links on a matching address, verified or not.
	//
	// Do not use this. It trusts a third party's unverified claim with full
	// access to an account, which is an account takeover anybody can perform
	// at any provider that does not verify addresses. It exists because a
	// policy nobody can name is a policy nobody can review — making this
	// reachable only by writing its name down is the point.
	LinkAlways
)

var (
	// ErrNoSocialProvider means no driver is registered under that name.
	ErrNoSocialProvider = errors.New("auth: no such social provider")

	// ErrStateMismatch means the callback's state did not match the session
	// that started the flow. The request is discarded.
	ErrStateMismatch = errors.New("auth: the social callback state does not match")

	// ErrLinkRefused means the identity's email belongs to an existing
	// account that the policy will not link automatically.
	ErrLinkRefused = errors.New("auth: this email already has an account; sign in and link it from your settings")

	// ErrNoSocialStore means Opts.SocialStore was not set.
	ErrNoSocialStore = errors.New("auth: no social store is configured")
)

// SocialStore is how this package reaches the application's users.
//
// Four transitions rather than a repository: each one is a decision the
// policy makes, and exposing a generic find-and-save would put the policy in
// every caller.
type SocialStore interface {
	// FindBySocialIdentity returns the user already linked to this provider
	// identity, or nil when there is none.
	//
	// Keyed on provider and subject, never on email. nil with a nil error is
	// the ordinary answer for somebody signing in for the first time.
	FindBySocialIdentity(ctx context.Context, provider, subject string) (UserProvider, error)

	// FindByEmail returns the account that owns an address, or nil.
	//
	// It must also report whether that account's own address is confirmed,
	// because LinkVerifiedOnly needs both halves and only the application
	// knows the second.
	FindByEmail(ctx context.Context, email string) (user UserProvider, emailConfirmed bool, err error)

	// LinkSocialIdentity attaches an identity to an existing user.
	//
	// It must be idempotent and it must refuse to move an identity that is
	// already attached to somebody else — that would be one person taking
	// over another's sign-in.
	LinkSocialIdentity(ctx context.Context, userID string, identity SocialIdentity) error

	// CreateFromSocialIdentity makes a new account.
	//
	// The user it returns has no password, which is the case LoginAs was
	// built for: Login compares a bcrypt hash and an empty hash fails against
	// every input, so such an account cannot be signed into by password even
	// by accident.
	CreateFromSocialIdentity(ctx context.Context, identity SocialIdentity) (UserProvider, error)
}

// socialStateKey is where the pending state lives in the session.
const socialStateKey = "auth:social_state"

// StartSocial begins a flow and returns where to send the browser.
//
// The state is generated here and stored in the session, which is the only
// place it can be bound to the browser that started the flow. A driver that
// invented its own would be checking a value against itself.
func (a *Auth) StartSocial(c app.Context, name string) (string, error) {
	provider, ok := a.SocialProvider(name)
	if !ok {
		return "", fmt.Errorf("%w: %q", ErrNoSocialProvider, name)
	}

	redirectURI, err := redirectURIFor(a.appURL, name)
	if err != nil {
		return "", err
	}

	// A session is required, and not incidentally: the state's whole job is
	// to be bound to the browser that started the flow, and there is nowhere
	// else to bind it. An application with DisableSession cannot offer social
	// sign-in, and saying so here beats a flow that appears to work until
	// somebody's callback is accepted from another tab.
	if a.sess == nil {
		return "", errors.New("auth: social sign-in needs a session, because " +
			"the CSRF state has to be bound to the browser that started the flow")
	}

	state, err := newSocialState()
	if err != nil {
		return "", err
	}
	// Stored under one key, so starting a second flow abandons the first
	// rather than leaving two states either of which would be accepted.
	a.sess.Put(c.RequestContext(), socialStateKey, name+":"+state)

	return provider.AuthorizeURL(state, redirectURI)
}

// CompleteSocial finishes a flow and signs somebody in.
//
// The order is the policy, and it is deliberate: the state first, because a
// request that fails it is not a request from anybody; then the linked
// identity, because somebody who has signed in this way before needs no
// decision made about them; then the email, which is the only branch where a
// judgement is involved.
func (a *Auth) CompleteSocial(c app.Context, name, code, state string) *LoginResult {
	provider, ok := a.SocialProvider(name)
	if !ok {
		return &LoginResult{Err: fmt.Errorf("%w: %q", ErrNoSocialProvider, name)}
	}
	if a.socialStore == nil {
		return &LoginResult{Err: ErrNoSocialStore}
	}
	if a.sess == nil {
		return &LoginResult{Err: errors.New("auth: social sign-in needs a session")}
	}

	// Popped, not read: a state is good for one callback, so a replayed
	// callback finds nothing left to match against. Popped *first*, before
	// anything else can fail, so a callback that errors for any reason still
	// consumes the state rather than leaving it for a second attempt.
	expected, _ := a.sess.PopAs[string](c.RequestContext(), socialStateKey)
	if expected == "" || !matchesSocialState(expected, name, state) {
		return &LoginResult{Err: ErrStateMismatch}
	}

	// The same redirect URI the authorize step sent, because providers
	// compare them and refuse the exchange when they differ.
	redirectURI, err := redirectURIFor(a.appURL, name)
	if err != nil {
		return &LoginResult{Err: err}
	}

	ctx := c.RequestContext()
	identity, err := provider.Identity(ctx, code, redirectURI)
	if err != nil {
		return &LoginResult{Err: err}
	}
	if identity == nil {
		return &LoginResult{Err: errors.New("auth: the provider returned no identity")}
	}
	identity.Provider = provider.Name()
	if err := identity.Validate(); err != nil {
		return &LoginResult{Err: err}
	}
	identity.Email = strings.ToLower(strings.TrimSpace(identity.Email))

	user, err := a.resolveSocialUser(ctx, *identity)
	if err != nil {
		return &LoginResult{Err: err}
	}
	return a.LoginAs(c, user)
}

// resolveSocialUser turns an identity into a user, applying the policy.
func (a *Auth) resolveSocialUser(ctx context.Context, identity SocialIdentity) (UserProvider, error) {
	// Already linked. No decision to make, and no email involved — which is
	// why the subject is what identities are keyed on.
	linked, err := a.socialStore.FindBySocialIdentity(ctx, identity.Provider, identity.Subject)
	if err != nil {
		return nil, err
	}
	if !isNilUser(linked) {
		return linked, nil
	}

	// No address to match on, so there is nothing to link to and nothing to
	// take over. A new account.
	if identity.Email == "" {
		return a.createFromSocial(ctx, identity)
	}

	existing, confirmed, err := a.socialStore.FindByEmail(ctx, identity.Email)
	if err != nil {
		return nil, err
	}
	if isNilUser(existing) {
		return a.createFromSocial(ctx, identity)
	}

	// An account owns this address. Whether this identity may join it is the
	// one judgement in the whole flow.
	switch a.linkPolicy {
	case LinkNever:
		return nil, ErrLinkRefused
	case LinkAlways:
		// Named explicitly by whoever configured it. See LinkAlways.
	default: // LinkVerifiedOnly
		if !identity.EmailVerified || !confirmed {
			return nil, ErrLinkRefused
		}
	}

	if err := a.socialStore.LinkSocialIdentity(ctx, existing.GetID(), identity); err != nil {
		return nil, err
	}
	return existing, nil
}

func (a *Auth) createFromSocial(ctx context.Context, identity SocialIdentity) (UserProvider, error) {
	user, err := a.socialStore.CreateFromSocialIdentity(ctx, identity)
	if err != nil {
		return nil, err
	}
	if isNilUser(user) {
		return nil, errors.New("auth: the store created no user and reported no error")
	}
	return user, nil
}

// SocialProvider returns a registered driver.
func (a *Auth) SocialProvider(name string) (SocialProvider, bool) {
	provider, ok := a.socialProviders[name]
	return provider, ok
}

// SocialProviders names every registered driver, for a sign-in page deciding
// which buttons to show.
func (a *Auth) SocialProviders() []string {
	names := make([]string, 0, len(a.socialProviders))
	for name := range a.socialProviders {
		names = append(names, name)
	}
	return names
}

// newSocialState returns an unguessable state value.
func newSocialState() (string, error) {
	buffer := make([]byte, 32)
	if _, err := rand.Read(buffer); err != nil {
		return "", fmt.Errorf("auth: generating a social state: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(buffer), nil
}

// matchesSocialState compares a stored state with a returned one.
//
// The provider name is part of the stored value, so a state issued for one
// provider cannot complete a flow at another — which would otherwise let a
// callback from a provider somebody controls consume a state issued for one
// they do not.
func matchesSocialState(stored, name, returned string) bool {
	wantName, wantState, found := strings.Cut(stored, ":")
	if !found || wantName != name || wantState == "" {
		return false
	}
	// Constant time, because this is a secret compared against something an
	// attacker supplies.
	return subtleCompare(wantState, returned)
}

// redirectURIFor is a helper for a driver's callback URL.
func redirectURIFor(base, name string) (string, error) {
	parsed, err := url.Parse(base)
	if err != nil {
		return "", fmt.Errorf("auth: %q is not a URL: %w", base, err)
	}
	parsed.Path = strings.TrimRight(parsed.Path, "/") + "/auth/" + name + "/callback"
	return parsed.String(), nil
}

// subtleCompare is crypto/subtle's comparison, on strings.
func subtleCompare(a, b string) bool {
	return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
}
