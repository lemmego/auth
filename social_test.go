package auth

import (
	"context"
	"errors"
	"strings"
	"testing"
)

// --- doubles -----------------------------------------------------------

type socialUser struct {
	id    string
	email string
}

func (u *socialUser) GetID() string       { return u.id }
func (u *socialUser) GetUsername() string { return u.email }
func (u *socialUser) GetPassword() string { return "" }

// fakeProvider is a driver that returns whatever the test sets.
type fakeProvider struct {
	name     string
	identity *SocialIdentity
	err      error
	// lastState and lastRedirect record what AuthorizeURL was handed, so a
	// test can assert the state was generated and bound rather than invented
	// by the driver.
	lastState    string
	lastRedirect string
}

func (p *fakeProvider) Name() string { return p.name }

func (p *fakeProvider) AuthorizeURL(state, redirectURI string) (string, error) {
	if state == "" {
		return "", errors.New("a driver must refuse an empty state")
	}
	p.lastState, p.lastRedirect = state, redirectURI
	return "https://provider.example/authorize?state=" + state, nil
}

func (p *fakeProvider) Identity(context.Context, string, string) (*SocialIdentity, error) {
	if p.err != nil {
		return nil, p.err
	}
	copied := *p.identity
	return &copied, nil
}

// fakeStore records what the policy decided to do.
type fakeStore struct {
	linked    map[string]UserProvider // "provider:subject" -> user
	byEmail   map[string]UserProvider
	confirmed map[string]bool

	linkedCalls  []string
	createdCalls []SocialIdentity
	createErr    error
}

func newFakeStore() *fakeStore {
	return &fakeStore{
		linked:    map[string]UserProvider{},
		byEmail:   map[string]UserProvider{},
		confirmed: map[string]bool{},
	}
}

func (s *fakeStore) FindBySocialIdentity(_ context.Context, provider, subject string) (UserProvider, error) {
	user, ok := s.linked[provider+":"+subject]
	if !ok {
		return nil, nil
	}
	return user, nil
}

func (s *fakeStore) FindByEmail(_ context.Context, email string) (UserProvider, bool, error) {
	user, ok := s.byEmail[email]
	if !ok {
		return nil, false, nil
	}
	return user, s.confirmed[email], nil
}

func (s *fakeStore) LinkSocialIdentity(_ context.Context, userID string, identity SocialIdentity) error {
	s.linkedCalls = append(s.linkedCalls, userID+"<-"+identity.Provider+":"+identity.Subject)
	return nil
}

func (s *fakeStore) CreateFromSocialIdentity(_ context.Context, identity SocialIdentity) (UserProvider, error) {
	if s.createErr != nil {
		return nil, s.createErr
	}
	s.createdCalls = append(s.createdCalls, identity)
	return &socialUser{id: "new", email: identity.Email}, nil
}

// socialAuth builds an Auth with a real session and a fake store.
func socialAuth(t *testing.T, provider *fakeProvider, store *fakeStore, policy LinkPolicy) (*Auth, context.Context) {
	t.Helper()

	a, ctx := newSessionAuth(t)
	a.jwtSecret = []byte("secret")
	a.socialProviders = map[string]SocialProvider{provider.name: provider}
	a.socialStore = store
	a.linkPolicy = policy
	a.appURL = "https://productshore.test"
	return a, ctx
}

func callbackContext(ctx context.Context) *fakeContext {
	return newFakeContext(ctx)
}

// --- the flow ----------------------------------------------------------

func TestStartSocialBindsAStateToTheSession(t *testing.T) {
	provider := &fakeProvider{name: "github"}
	a, ctx := socialAuth(t, provider, newFakeStore(), LinkVerifiedOnly)
	c := callbackContext(ctx)

	where, err := a.StartSocial(c, "github")
	if err != nil {
		t.Fatalf("StartSocial: %v", err)
	}

	if provider.lastState == "" {
		t.Fatal("the driver was handed no state, so there is nothing bound " +
			"to this browser and the callback could come from anywhere")
	}
	if !strings.Contains(where, provider.lastState) {
		t.Fatalf("the redirect does not carry the state: %s", where)
	}
	// The redirect URI is built from AppURL rather than from the request,
	// because a provider compares it against what was registered and a proxy
	// that rewrites Host would break every sign-in in production only.
	if provider.lastRedirect != "https://productshore.test/auth/github/callback" {
		t.Fatalf("got redirect URI %q", provider.lastRedirect)
	}
}

func TestACallbackWithTheWrongStateIsRefused(t *testing.T) {
	provider := &fakeProvider{
		name:     "github",
		identity: &SocialIdentity{Subject: "1", Email: "ada@example.com", EmailVerified: true},
	}
	a, ctx := socialAuth(t, provider, newFakeStore(), LinkVerifiedOnly)
	c := callbackContext(ctx)

	if _, err := a.StartSocial(c, "github"); err != nil {
		t.Fatalf("StartSocial: %v", err)
	}

	result := a.CompleteSocial(c, "github", "code", "not-the-state")
	if !errors.Is(result.Err, ErrStateMismatch) {
		t.Fatalf("got %v, want ErrStateMismatch", result.Err)
	}
}

// A state is good for one callback. Replaying it finds nothing left.
func TestAReplayedCallbackIsRefused(t *testing.T) {
	provider := &fakeProvider{
		name:     "github",
		identity: &SocialIdentity{Subject: "1", Email: "ada@example.com", EmailVerified: true},
	}
	store := newFakeStore()
	a, ctx := socialAuth(t, provider, store, LinkVerifiedOnly)
	c := callbackContext(ctx)

	if _, err := a.StartSocial(c, "github"); err != nil {
		t.Fatalf("StartSocial: %v", err)
	}
	state := provider.lastState

	if result := a.CompleteSocial(c, "github", "code", state); result.Err != nil {
		t.Fatalf("the first callback failed: %v", result.Err)
	}
	result := a.CompleteSocial(c, "github", "code", state)
	if !errors.Is(result.Err, ErrStateMismatch) {
		t.Fatalf("got %v, want ErrStateMismatch on a replay", result.Err)
	}
}

// A state issued for one provider must not complete a flow at another, or a
// callback from a provider somebody controls could consume a state issued for
// one they do not.
func TestAStateIssuedForOneProviderCannotCompleteAnother(t *testing.T) {
	github := &fakeProvider{name: "github"}
	google := &fakeProvider{
		name:     "google",
		identity: &SocialIdentity{Subject: "1", Email: "ada@example.com", EmailVerified: true},
	}
	a, ctx := socialAuth(t, github, newFakeStore(), LinkVerifiedOnly)
	a.socialProviders["google"] = google
	c := callbackContext(ctx)

	if _, err := a.StartSocial(c, "github"); err != nil {
		t.Fatalf("StartSocial: %v", err)
	}

	result := a.CompleteSocial(c, "google", "code", github.lastState)
	if !errors.Is(result.Err, ErrStateMismatch) {
		t.Fatalf("got %v, want ErrStateMismatch", result.Err)
	}
}

// --- the policy --------------------------------------------------------

// completeWith runs a whole flow and returns the result.
func completeWith(t *testing.T, store *fakeStore, policy LinkPolicy, identity SocialIdentity) (*Auth, *LoginResult) {
	t.Helper()

	provider := &fakeProvider{name: "github", identity: &identity}
	a, ctx := socialAuth(t, provider, store, policy)
	c := callbackContext(ctx)

	if _, err := a.StartSocial(c, "github"); err != nil {
		t.Fatalf("StartSocial: %v", err)
	}
	return a, a.CompleteSocial(c, "github", "code", provider.lastState)
}

// An identity already linked needs no decision, and no email is consulted —
// which is the reason identities are keyed on the provider's subject.
func TestAnAlreadyLinkedIdentitySignsStraightIn(t *testing.T) {
	store := newFakeStore()
	existing := &socialUser{id: "7", email: "ada@example.com"}
	store.linked["github:1"] = existing
	// A different address on the identity, which must not matter.
	_, result := completeWith(t, store, LinkVerifiedOnly, SocialIdentity{
		Subject: "1", Email: "somewhere-else@example.com", EmailVerified: false,
	})

	if result.Err != nil {
		t.Fatalf("an already-linked identity was refused: %v", result.Err)
	}
	if len(store.linkedCalls) != 0 || len(store.createdCalls) != 0 {
		t.Fatalf("the store was asked to link or create: %v %v",
			store.linkedCalls, store.createdCalls)
	}
}

func TestAnUnknownEmailCreatesAnAccount(t *testing.T) {
	store := newFakeStore()
	_, result := completeWith(t, store, LinkVerifiedOnly, SocialIdentity{
		Subject: "1", Email: "new@example.com", EmailVerified: true, Handle: "ada",
	})

	if result.Err != nil {
		t.Fatalf("a new identity was refused: %v", result.Err)
	}
	if len(store.createdCalls) != 1 {
		t.Fatalf("the store created %d accounts, want 1", len(store.createdCalls))
	}
	if store.createdCalls[0].Handle != "ada" {
		t.Fatalf("the suggested handle was lost: %v", store.createdCalls[0])
	}
}

// No address means nothing to match against, so there is nothing to take
// over either.
func TestAnIdentityWithNoEmailCreatesAnAccount(t *testing.T) {
	store := newFakeStore()
	store.byEmail[""] = &socialUser{id: "7"}

	_, result := completeWith(t, store, LinkVerifiedOnly, SocialIdentity{Subject: "1"})
	if result.Err != nil {
		t.Fatalf("an identity with no email was refused: %v", result.Err)
	}
	if len(store.createdCalls) != 1 {
		t.Fatalf("created %d accounts, want 1", len(store.createdCalls))
	}
	if len(store.linkedCalls) != 0 {
		t.Fatal("an identity with no email was linked to an account by its " +
			"empty address")
	}
}

// Both halves verified is the only automatic link.
func TestAVerifiedIdentityLinksToAConfirmedAccount(t *testing.T) {
	store := newFakeStore()
	store.byEmail["ada@example.com"] = &socialUser{id: "7", email: "ada@example.com"}
	store.confirmed["ada@example.com"] = true

	_, result := completeWith(t, store, LinkVerifiedOnly, SocialIdentity{
		Subject: "1", Email: "ada@example.com", EmailVerified: true,
	})

	if result.Err != nil {
		t.Fatalf("a verified identity was refused: %v", result.Err)
	}
	if len(store.linkedCalls) != 1 {
		t.Fatalf("linked %d times, want 1", len(store.linkedCalls))
	}
	if len(store.createdCalls) != 0 {
		t.Fatal("a second account was created for an address that already had one")
	}
}

// This is the takeover the policy exists to prevent: anybody can put
// somebody else's address on a throwaway account at most providers.
func TestAnUnverifiedProviderEmailCannotClaimAnAccount(t *testing.T) {
	store := newFakeStore()
	store.byEmail["ada@example.com"] = &socialUser{id: "7", email: "ada@example.com"}
	store.confirmed["ada@example.com"] = true

	_, result := completeWith(t, store, LinkVerifiedOnly, SocialIdentity{
		Subject: "99", Email: "ada@example.com", EmailVerified: false,
	})

	if !errors.Is(result.Err, ErrLinkRefused) {
		t.Fatalf("got %v, want ErrLinkRefused — an unverified provider email "+
			"must not reach an existing account", result.Err)
	}
	if len(store.linkedCalls) != 0 {
		t.Fatal("the identity was linked anyway")
	}
	if len(store.createdCalls) != 0 {
		t.Fatal("a second account was created for an address that already had one")
	}
}

// The other half: if this application never confirmed the account's own
// address, it has not proved the owner reads that inbox either.
func TestAnUnconfirmedLocalAccountIsNotLinked(t *testing.T) {
	store := newFakeStore()
	store.byEmail["ada@example.com"] = &socialUser{id: "7", email: "ada@example.com"}
	store.confirmed["ada@example.com"] = false

	_, result := completeWith(t, store, LinkVerifiedOnly, SocialIdentity{
		Subject: "1", Email: "ada@example.com", EmailVerified: true,
	})

	if !errors.Is(result.Err, ErrLinkRefused) {
		t.Fatalf("got %v, want ErrLinkRefused", result.Err)
	}
}

func TestLinkNeverRefusesEvenWhenBothAreVerified(t *testing.T) {
	store := newFakeStore()
	store.byEmail["ada@example.com"] = &socialUser{id: "7", email: "ada@example.com"}
	store.confirmed["ada@example.com"] = true

	_, result := completeWith(t, store, LinkNever, SocialIdentity{
		Subject: "1", Email: "ada@example.com", EmailVerified: true,
	})

	if !errors.Is(result.Err, ErrLinkRefused) {
		t.Fatalf("got %v, want ErrLinkRefused", result.Err)
	}
}

// Reachable only by writing its name down, which is the point of it existing
// at all: a policy nobody can name is a policy nobody can review.
func TestLinkAlwaysLinksOnAMatchingAddress(t *testing.T) {
	store := newFakeStore()
	store.byEmail["ada@example.com"] = &socialUser{id: "7", email: "ada@example.com"}
	store.confirmed["ada@example.com"] = false

	_, result := completeWith(t, store, LinkAlways, SocialIdentity{
		Subject: "1", Email: "ada@example.com", EmailVerified: false,
	})

	if result.Err != nil {
		t.Fatalf("LinkAlways refused: %v", result.Err)
	}
	if len(store.linkedCalls) != 1 {
		t.Fatalf("linked %d times, want 1", len(store.linkedCalls))
	}
}

func TestAnIdentityWithNoSubjectIsRefused(t *testing.T) {
	store := newFakeStore()
	_, result := completeWith(t, store, LinkVerifiedOnly, SocialIdentity{
		Email: "ada@example.com", EmailVerified: true,
	})

	if result.Err == nil || !strings.Contains(result.Err.Error(), "subject") {
		t.Fatalf("got %v, want a refusal naming the missing subject", result.Err)
	}
}

func TestAnEmailIsLowercasedBeforeItIsMatched(t *testing.T) {
	store := newFakeStore()
	store.byEmail["ada@example.com"] = &socialUser{id: "7", email: "ada@example.com"}
	store.confirmed["ada@example.com"] = true

	_, result := completeWith(t, store, LinkVerifiedOnly, SocialIdentity{
		Subject: "1", Email: "  Ada@Example.COM  ", EmailVerified: true,
	})

	if result.Err != nil {
		t.Fatalf("a differently-cased address did not match: %v", result.Err)
	}
	if len(store.linkedCalls) != 1 {
		t.Fatalf("linked %d times, want 1 — an address that differs only in "+
			"case is the same address", len(store.linkedCalls))
	}
}

func TestAnUnknownProviderIsRefused(t *testing.T) {
	a, ctx := socialAuth(t, &fakeProvider{name: "github"}, newFakeStore(), LinkVerifiedOnly)
	c := callbackContext(ctx)

	if _, err := a.StartSocial(c, "gitlab"); !errors.Is(err, ErrNoSocialProvider) {
		t.Fatalf("got %v, want ErrNoSocialProvider", err)
	}
	result := a.CompleteSocial(c, "gitlab", "code", "state")
	if !errors.Is(result.Err, ErrNoSocialProvider) {
		t.Fatalf("got %v, want ErrNoSocialProvider", result.Err)
	}
}

// --- configuration -----------------------------------------------------

func TestProvidersWithoutAStoreAreRefusedAtBoot(t *testing.T) {
	a := New()
	err := a.wireSocial(&Opts{
		SocialProviders: []SocialProvider{&fakeProvider{name: "github"}},
		AppURL:          "https://productshore.test",
	})
	if err == nil {
		t.Fatal("a provider with no store was accepted, so nothing could " +
			"resolve who is signing in")
	}
	if !strings.Contains(err.Error(), "SocialStore") {
		t.Fatalf("the refusal does not name the missing field: %v", err)
	}
}

func TestProvidersWithoutAnAppURLAreRefusedAtBoot(t *testing.T) {
	a := New()
	err := a.wireSocial(&Opts{
		SocialProviders: []SocialProvider{&fakeProvider{name: "github"}},
		SocialStore:     newFakeStore(),
	})
	if err == nil {
		t.Fatal("a provider with no AppURL was accepted")
	}
	if !strings.Contains(err.Error(), "AppURL") {
		t.Fatalf("the refusal does not name the missing field: %v", err)
	}
}

func TestTwoProvidersWithOneNameAreRefused(t *testing.T) {
	a := New()
	err := a.wireSocial(&Opts{
		SocialProviders: []SocialProvider{
			&fakeProvider{name: "github"},
			&fakeProvider{name: "github"},
		},
		SocialStore: newFakeStore(),
		AppURL:      "https://productshore.test",
	})
	if err == nil {
		t.Fatal("two providers claiming one name were accepted, so one of " +
			"them is silently unreachable")
	}
}

func TestNoProvidersIsNotAnError(t *testing.T) {
	a := New()
	if err := a.wireSocial(&Opts{}); err != nil {
		t.Fatalf("an application with no social sign-in failed to boot: %v", err)
	}
	if len(a.SocialProviders()) != 0 {
		t.Fatal("providers appeared from nowhere")
	}
}

// Social sign-in cannot work without a session, because the state has
// nowhere else to be bound. Said at the first call rather than discovered
// when a callback is accepted from the wrong tab.
func TestSocialSignInNeedsASession(t *testing.T) {
	a := New()
	a.socialProviders = map[string]SocialProvider{"github": &fakeProvider{name: "github"}}
	a.socialStore = newFakeStore()
	a.appURL = "https://productshore.test"

	c := newFakeContext(context.Background())
	if _, err := a.StartSocial(c, "github"); err == nil ||
		!strings.Contains(err.Error(), "session") {
		t.Fatalf("got %v, want a refusal naming the session", err)
	}
}
