package auth

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/lemmego/api/app"
)

// A deleted account is an ordinary event, not a fault. It is a 401, and the
// credential is destroyed so the next request is simply anonymous rather than
// another futile lookup of a dead id on every request until expiry.
func TestDeletedUserIsUnauthorizedAndTheCredentialIsDestroyed(t *testing.T) {
	a, ctx := newSessionAuth(t)
	a.jwtSecret = []byte("secret")
	a.userLoader = func(app.Context, string) (any, error) { return nil, ErrUserNotFound }
	a.sess.Put(ctx, UserIDKey, "7")

	c := newCheckContext(ctx, nil)
	err := a.Check(c)

	if !errors.Is(err, ErrUserNotFound) {
		t.Fatalf("Check = %v, want ErrUserNotFound", err)
	}
	var storeDown *UserStoreUnavailableError
	if errors.As(err, &storeDown) {
		t.Fatal("a deleted user was reported as an outage")
	}
	if a.sess.Get(ctx, UserIDKey) != nil {
		t.Error("the session survived a user who no longer exists")
	}
	if cookie := c.cookie("jwt"); cookie == nil || cookie.MaxAge >= 0 {
		t.Error("the jwt cookie was not expired")
	}
}

// The distinction that makes this design safe: a store that could not answer
// must not log anyone out. Conflating it with "not found" means a database
// blip logs every user out and then stampedes the login page when they all
// retry.
func TestLoaderFailureIsNotALogout(t *testing.T) {
	a, ctx := newSessionAuth(t)
	a.jwtSecret = []byte("secret")
	a.userLoader = func(app.Context, string) (any, error) {
		return nil, errors.New("dial tcp 127.0.0.1:5432: connection refused")
	}
	a.sess.Put(ctx, UserIDKey, "7")

	c := newCheckContext(ctx, nil)
	err := a.Check(c)

	var storeDown *UserStoreUnavailableError
	if !errors.As(err, &storeDown) {
		t.Fatalf("Check = %v, want a UserStoreUnavailableError", err)
	}
	if got := storeDown.GetHttpMessage().Status; got != http.StatusServiceUnavailable {
		t.Errorf("status = %d, want 503", got)
	}
	if errors.Is(err, ErrUserNotFound) {
		t.Error("an outage was reported as a missing user")
	}
	// The credential must survive: when the database comes back the user is
	// still logged in.
	if a.sess.Get(ctx, UserIDKey) == nil {
		t.Error("an outage logged the user out")
	}
	if c.cookie("jwt") != nil {
		t.Error("an outage expired the jwt cookie")
	}
}

// A cancelled request is the client hanging up. Classing it as an outage
// buries the real ones in the log.
func TestCancelledRequestIsNotReportedAsAnOutage(t *testing.T) {
	a, ctx := newSessionAuth(t)
	a.userLoader = func(app.Context, string) (any, error) { return nil, context.Canceled }
	a.sess.Put(ctx, UserIDKey, "7")

	err := a.Check(newCheckContext(ctx, nil))

	var storeDown *UserStoreUnavailableError
	if errors.As(err, &storeDown) {
		t.Fatal("a cancelled request was reported as a store outage")
	}
	if !errors.Is(err, context.Canceled) {
		t.Errorf("Check = %v, want the cancellation to survive", err)
	}
}

// A typed nil is not nil as an any, so without an explicit check it would
// satisfy both the already-resolved short-circuit and UserAs's assertion —
// and the first handler to read a field would dereference nil.
func TestNilUserFromTheLoaderDoesNotAuthenticate(t *testing.T) {
	for name, returned := range map[string]any{
		"untyped nil":            nil,
		"typed nil pointer":      (*testUser)(nil),
		"typed nil boxed in any": any((*testUser)(nil)),
	} {
		t.Run(name, func(t *testing.T) {
			a, ctx := newSessionAuth(t)
			a.userLoader = func(app.Context, string) (any, error) { return returned, nil }
			a.sess.Put(ctx, UserIDKey, "7")

			c := newCheckContext(ctx, nil)
			if err := a.Check(c); err == nil {
				t.Fatal("a nil user authenticated")
			}
			if AuthUser(c) != nil {
				t.Fatalf("a nil user reached the context as %#v", AuthUser(c))
			}
			// A second Check must still fail rather than short-circuit on it.
			if err := a.Check(c); err == nil {
				t.Fatal("a second Check admitted the request")
			}
		})
	}
}

// Three middlewares against a store with a thirty-second timeout is ninety
// seconds of a held connection on one dying request.
func TestLoadFailureIsMemoisedForTheRequest(t *testing.T) {
	a, ctx := newSessionAuth(t)
	calls := 0
	a.userLoader = func(app.Context, string) (any, error) {
		calls++
		return nil, errors.New("store is down")
	}
	a.sess.Put(ctx, UserIDKey, "7")

	c := newCheckContext(ctx, nil)
	for i := 0; i < 3; i++ {
		_ = a.Check(c)
	}
	if calls != 1 {
		t.Fatalf("the loader ran %d times across three checks, want 1", calls)
	}
}

// The loader must run once per request even on success, since Protected, a
// group guard and the handler may each ask.
func TestLoaderRunsOncePerRequest(t *testing.T) {
	a, ctx := newSessionAuth(t)
	loader, calls := loaderFor(&testUser{ID: "7", Email: "ada@example.com"})
	a.userLoader = loader
	a.sess.Put(ctx, UserIDKey, "7")

	c := newCheckContext(ctx, nil)
	for i := 0; i < 3; i++ {
		if err := a.Check(c); err != nil {
			t.Fatal(err)
		}
	}
	if *calls != 1 {
		t.Fatalf("the loader ran %d times across three checks, want 1", *calls)
	}
}

// A misconfiguration is not a rejected credential. Answering 401 would send
// an operator hunting for a bad password.
func TestNoLoaderIsAServerErrorNotAnUnauthorized(t *testing.T) {
	a, ctx := newSessionAuth(t)
	a.sess.Put(ctx, UserIDKey, "7")

	c := newCheckContext(ctx, nil)
	if err := a.Check(c); !errors.Is(err, ErrNoUserLoader) {
		t.Fatalf("Check = %v, want ErrNoUserLoader", err)
	}
}

// sub identifies the user now, so a configured claim overriding it would let
// anyone who can set JwtClaims mint a token for any account.
func TestConfiguredClaimsCannotOverrideTheSubject(t *testing.T) {
	a := &Auth{
		jwtSecret: []byte("secret"),
		jwtClaims: jwt.MapClaims{"sub": "999", "role": "admin"},
	}
	user := testLoginUser(t)

	result := a.Login(newFakeContext(context.Background()), user, user.Email, "password")
	if result.Err != nil {
		t.Fatal(result.Err)
	}

	subject, err := a.jwtSubject(result.JwtToken)
	if err != nil {
		t.Fatal(err)
	}
	if subject != user.GetID() {
		t.Fatalf("sub = %q, want the real user id %q", subject, user.GetID())
	}
}

// The token is a pointer to a row, not a copy of one. It is signed, not
// encrypted, so anything embedded in it is readable by whoever holds it.
func TestJWTCarriesOnlyASubjectClaim(t *testing.T) {
	a := &Auth{jwtSecret: []byte("secret")}
	user := testLoginUser(t)

	result := a.Login(newFakeContext(context.Background()), user, user.Email, "password")
	if result.Err != nil {
		t.Fatal(result.Err)
	}

	segments := strings.Split(result.JwtToken, ".")
	if len(segments) != 3 {
		t.Fatalf("token has %d segments", len(segments))
	}
	payload, err := jwt.NewParser().DecodeSegment(segments[1])
	if err != nil {
		t.Fatal(err)
	}
	var claims map[string]any
	if err := json.Unmarshal(payload, &claims); err != nil {
		t.Fatal(err)
	}

	if _, present := claims["user"]; present {
		t.Error("the token still embeds the user object")
	}
	for _, claim := range []string{"sub", "iat", "exp"} {
		if _, present := claims[claim]; !present {
			t.Errorf("the token has no %s claim", claim)
		}
	}
	// The strongest form of the assertion: nothing about the user is legible
	// in the token at all.
	if strings.Contains(result.JwtToken, "email") || strings.Contains(string(payload), user.GetUsername()) {
		t.Errorf("the token leaks user data: %s", payload)
	}
}

// A user with no identifier would mint a credential whose very next request
// fails, because sub is what the loader is handed.
func TestLoginRejectsAUserWithNoIdentifier(t *testing.T) {
	a := &Auth{jwtSecret: []byte("secret")}

	// A model whose GetID is empty — an unsaved record, or an implementation
	// that forgot to fill it in. Note auth.User{ID: 0} does NOT qualify: its
	// GetID returns "0", which is a perfectly well-formed id that the loader
	// will simply fail to find.
	user := &idlessUser{password: testLoginUser(t).Password}

	result := a.Login(newFakeContext(context.Background()), user, "user@example.com", "password")
	if !errors.Is(result.Err, ErrMissingUserID) {
		t.Fatalf("Login = %v, want ErrMissingUserID", result.Err)
	}
	if result.JwtToken != "" {
		t.Error("a token was minted for a user with no identifier")
	}
}

// A credential from before the format changed names nobody. The loader must
// report that as not-found, so it is a 401 and not a fleet-wide outage on the
// day of the upgrade.
func TestPreviousFormatTokensAreRejected(t *testing.T) {
	a := &Auth{jwtSecret: []byte("secret")}

	// A loader shaped the way the scaffold's is: an id it cannot parse is a
	// user that does not exist.
	var handed string
	a.userLoader = func(_ app.Context, id string) (any, error) {
		handed = id
		if _, err := parseTestID(id); err != nil {
			return nil, ErrUserNotFound
		}
		return &testUser{ID: id}, nil
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"user": `{"id":7,"email":"ada@example.com"}`,
		"sub":  "7|ada@example.com",
		"exp":  time.Now().Add(time.Hour).Unix(),
	})
	raw, err := token.SignedString(a.jwtSecret)
	if err != nil {
		t.Fatal(err)
	}

	request := httptest.NewRequest(http.MethodGet, "/", nil)
	request.Header.Set("Authorization", "Bearer "+raw)
	err = a.Check(newCheckContext(nil, request))

	if !errors.Is(err, ErrUserNotFound) {
		t.Fatalf("Check = %v, want ErrUserNotFound", err)
	}
	var storeDown *UserStoreUnavailableError
	if errors.As(err, &storeDown) {
		t.Fatal("a stale credential was reported as an outage; on upgrade day that is a fleet-wide 503")
	}
	if handed != "7|ada@example.com" {
		t.Errorf("the loader was handed %q, want the whole composite subject", handed)
	}
}

func parseTestID(id string) (int, error) {
	n := 0
	for _, r := range id {
		if r < '0' || r > '9' {
			return 0, errors.New("not a number")
		}
		n = n*10 + int(r-'0')
	}
	if id == "" {
		return 0, errors.New("empty")
	}
	return n, nil
}

// idlessUser satisfies UserProvider but has no identifier.
type idlessUser struct{ password string }

func (u *idlessUser) GetID() string       { return "" }
func (u *idlessUser) GetUsername() string { return "user@example.com" }
func (u *idlessUser) GetPassword() string { return u.password }
