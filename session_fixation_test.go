package auth

import (
	"context"
	"errors"
	"net/http"
	"testing"
	"time"

	"github.com/lemmego/api/app"

	"github.com/alexedwards/scs/v2"
	"github.com/alexedwards/scs/v2/memstore"
	"github.com/lemmego/api/session"
)

// newSessionAuth returns an Auth backed by a real session manager over an
// in-memory store, plus a context carrying a loaded session.
func newSessionAuth(t *testing.T) (*Auth, context.Context) {
	t.Helper()

	manager := scs.New()
	manager.Store = memstore.New()
	manager.Lifetime = time.Hour

	ctx, err := manager.Load(context.Background(), "")
	if err != nil {
		t.Fatalf("loading a session: %v", err)
	}
	return &Auth{sess: &session.Session{SessionManager: manager}}, ctx
}

// commit writes the session and returns the id it was stored under, which is
// what a browser would carry in its cookie.
func commit(t *testing.T, a *Auth, ctx context.Context) string {
	t.Helper()
	token, _, err := a.sess.Commit(ctx)
	if err != nil {
		t.Fatalf("committing the session: %v", err)
	}
	return token
}

// Logging in must change the session id. Otherwise an attacker who plants a
// session cookie in the victim's browser before they log in still holds a
// valid id afterwards, authenticated as them.
func TestLoginRotatesTheSessionID(t *testing.T) {
	a, ctx := newSessionAuth(t)

	// The id an attacker fixed on the victim before they logged in.
	a.sess.Put(ctx, "visited", "/pricing")
	fixated := commit(t, a, ctx)
	if fixated == "" {
		t.Fatal("expected the pre-login session to have an id")
	}

	user := testLoginUser(t)
	if result := a.Login(fakeContext{ctx: ctx}, user, user.Email, "password"); result.Err != nil {
		t.Fatalf("login failed: %v", result.Err)
	}

	if after := a.sess.Token(ctx); after == fixated {
		t.Fatal("the session id survived login, so session fixation is still possible")
	}
	if a.sess.Get(ctx, UserKey) == nil {
		t.Fatal("login did not store the user in the session")
	}

	// The rotation must carry existing data over. The CSRF middleware keeps
	// its token in the session, so dropping the data here would 419 the very
	// next request the user makes.
	if got := a.sess.GetString(ctx, "visited"); got != "/pricing" {
		t.Fatalf("session data was lost across login: visited = %q", got)
	}

	// The old id must no longer resolve to a session in the store.
	stale, err := a.sess.Load(context.Background(), fixated)
	if err != nil {
		t.Fatalf("loading the old id: %v", err)
	}
	if a.sess.Get(stale, UserKey) != nil {
		t.Fatal("the pre-login session id is still authenticated")
	}
}

// Logging out must destroy the session, not merely remove the user key, so the
// id it was authenticated under stops being valid.
func TestLogoutDestroysTheSession(t *testing.T) {
	a, ctx := newSessionAuth(t)

	user := testLoginUser(t)
	if result := a.Login(fakeContext{ctx: ctx}, user, user.Email, "password"); result.Err != nil {
		t.Fatalf("login failed: %v", result.Err)
	}
	a.sess.Put(ctx, "cart", "3 items")
	authenticated := commit(t, a, ctx)

	a.clearSession(ctx)

	if a.sess.Get(ctx, UserKey) != nil {
		t.Fatal("the user survived logout")
	}
	if a.sess.GetString(ctx, "cart") != "" {
		t.Fatal("session data outlived the logged-in user")
	}

	stale, err := a.sess.Load(context.Background(), authenticated)
	if err != nil {
		t.Fatalf("loading the old id: %v", err)
	}
	if a.sess.Get(stale, UserKey) != nil {
		t.Fatal("the session id used before logout is still authenticated")
	}
}

// A flash message set on the way to the login page must survive, landing in a
// fresh session rather than being swallowed by the destroy.
func TestWritesAfterLogoutStartANewSession(t *testing.T) {
	a, ctx := newSessionAuth(t)

	user := testLoginUser(t)
	if result := a.Login(fakeContext{ctx: ctx}, user, user.Email, "password"); result.Err != nil {
		t.Fatalf("login failed: %v", result.Err)
	}
	a.clearSession(ctx)
	a.sess.Put(ctx, "flash", "You have been logged out.")

	token := commit(t, a, ctx)
	if token == "" {
		t.Fatal("expected a new session id for the post-logout write")
	}

	fresh, err := a.sess.Load(context.Background(), token)
	if err != nil {
		t.Fatalf("loading the new id: %v", err)
	}
	if got := a.sess.GetString(fresh, "flash"); got != "You have been logged out." {
		t.Fatalf("flash message did not survive logout: %q", got)
	}
	if a.sess.Get(fresh, UserKey) != nil {
		t.Fatal("the new session is authenticated")
	}
}

// If the store cannot rotate the id, the login must fail rather than complete
// under the id the attacker chose.
func TestLoginFailsWhenTheSessionCannotBeRotated(t *testing.T) {
	a, ctx := newSessionAuth(t)

	// Establish a real session first: RenewToken only touches the store when
	// there is an existing id to delete.
	a.sess.Put(ctx, "seed", "value")
	commit(t, a, ctx)
	a.sess.Store = failingStore{}

	user := testLoginUser(t)
	result := a.Login(fakeContext{ctx: ctx}, user, user.Email, "password")
	if result.Err == nil {
		t.Fatal("expected login to fail when the session id cannot be rotated")
	}
	if a.sess.Get(ctx, UserKey) != nil {
		t.Fatal("a failed rotation still wrote the user into the session")
	}
}

// Auth without a session (JWT-only) must not panic on either path.
func TestSessionlessAuthLogsInAndOut(t *testing.T) {
	a := &Auth{jwtSecret: []byte("secret")}
	user := testLoginUser(t)

	if result := a.Login(nil, user, user.Email, "password"); result.Err != nil {
		t.Fatalf("sessionless login failed: %v", result.Err)
	}
	a.clearSession(context.Background())
}

// fakeContext supplies the two things Login touches on an app.Context — the
// request context and the JWT cookie — and leaves the rest of the interface
// embedded, so a call to anything else fails loudly rather than silently.
type fakeContext struct {
	app.Context
	ctx context.Context
}

func (f fakeContext) RequestContext() context.Context { return f.ctx }

func (f fakeContext) SetCookie(*http.Cookie) app.CookieGetSetter { return nil }

// failingStore rejects writes, standing in for a store that is down.
type failingStore struct{}

var errStoreDown = errors.New("store is down")

func (failingStore) Delete(string) error                    { return errStoreDown }
func (failingStore) Find(string) ([]byte, bool, error)      { return nil, false, errStoreDown }
func (failingStore) Commit(string, []byte, time.Time) error { return errStoreDown }
