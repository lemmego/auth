package auth

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/lemmego/api/app"
)

// checkContext carries everything Check reads: the request, its headers, the
// request context, and the per-request bag Check writes the user into.
type checkContext struct {
	app.Context
	ctx     context.Context
	req     *http.Request
	values  map[string]any
	cookies []*http.Cookie
}

func newCheckContext(ctx context.Context, req *http.Request) *checkContext {
	if ctx == nil {
		ctx = context.Background()
	}
	if req == nil {
		req = httptest.NewRequest(http.MethodGet, "/", nil)
	}
	return &checkContext{ctx: ctx, req: req, values: map[string]any{}}
}

func (c *checkContext) RequestContext() context.Context { return c.ctx }
func (c *checkContext) Request() *http.Request          { return c.req }
func (c *checkContext) Header(key string) string        { return c.req.Header.Get(key) }
func (c *checkContext) Set(key string, value any)       { c.values[key] = value }
func (c *checkContext) Get(key string) any              { return c.values[key] }

// Cookies are recorded rather than discarded: revoking a credential is
// observable only through them.
func (c *checkContext) SetCookie(cookie *http.Cookie) app.CookieGetSetter {
	c.cookies = append(c.cookies, cookie)
	return nil
}

// cookie returns the last cookie written under name.
func (c *checkContext) cookie(name string) *http.Cookie {
	for i := len(c.cookies) - 1; i >= 0; i-- {
		if c.cookies[i].Name == name {
			return c.cookies[i]
		}
	}
	return nil
}

// App is unused by the tests' own loaders, which close over what they need,
// but Check hands it to them so it has to exist.
func (c *checkContext) App() app.App { return nil }

// signedUserToken mints a token the way Login now does: a subject and
// nothing else about the user.
func signedUserToken(t *testing.T, secret []byte, subject string) string {
	t.Helper()
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"sub": subject,
		"exp": time.Now().Add(time.Hour).Unix(),
	})
	raw, err := token.SignedString(secret)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

// testUser is the application's own user type, as far as these tests are
// concerned.
type testUser struct {
	ID    string
	Email string
}

func (u *testUser) GetID() string       { return u.ID }
func (u *testUser) GetUsername() string { return u.Email }
func (u *testUser) GetPassword() string { return "" }

// loaderFor returns a loader over a fixed set of users, and a counter, so a
// test can assert how many times it ran.
func loaderFor(users ...*testUser) (UserLoader, *int) {
	byID := map[string]*testUser{}
	for _, user := range users {
		byID[user.ID] = user
	}
	calls := 0
	return func(_ app.Context, id string) (any, error) {
		calls++
		user, ok := byID[id]
		if !ok {
			return nil, fmt.Errorf("%w: %q", ErrUserNotFound, id)
		}
		return user, nil
	}, &calls
}

// The claim this whole design makes: one handler, one assertion, both
// transports.
//
// Before, the session path set the application's own type and the JWT path
// set a map[string]any decoded from the token — so the same handler saw a
// different type depending on how the request had authenticated. That is
// FINDINGS.md's first entry, written as a test.
func TestTheSameHandlerSeesTheSameTypeOnBothPaths(t *testing.T) {
	ada := &testUser{ID: "7", Email: "ada@example.com"}

	// The handler under test. It is written once and must work for both.
	handler := func(c app.Context) error {
		user, ok := UserAs[*testUser](c)
		if !ok {
			return fmt.Errorf("not the application's type: got %T", AuthUser(c))
		}
		if user.Email != "ada@example.com" {
			return fmt.Errorf("wrong user: %+v", user)
		}
		return nil
	}

	for _, transport := range []string{"session", "bearer"} {
		t.Run(transport, func(t *testing.T) {
			a, sessionCtx := newSessionAuth(t)
			a.jwtSecret = []byte("secret")
			a.userLoader, _ = loaderFor(ada)

			request := httptest.NewRequest(http.MethodGet, "/", nil)
			switch transport {
			case "session":
				a.sess.Put(sessionCtx, UserIDKey, ada.ID)
			case "bearer":
				request.Header.Set("Authorization", "Bearer "+signedUserToken(t, a.jwtSecret, ada.ID))
			}

			c := newCheckContext(sessionCtx, request)
			if err := a.Check(c); err != nil {
				t.Fatalf("Check: %v", err)
			}
			if err := handler(c); err != nil {
				t.Fatal(err)
			}
		})
	}
}

// A user another middleware has already established is authenticated. This is
// the seam an external verifier hangs off without auth depending on it.
func TestCheckHonoursAPreEstablishedUser(t *testing.T) {
	a, ctx := newSessionAuth(t)
	a.jwtSecret = []byte("secret")
	a.userLoader, _ = loaderFor()

	c := newCheckContext(ctx, nil)
	c.Set(UserKey, &testUser{ID: "9", Email: "elsewhere@example.com"})

	if err := a.Check(c); err != nil {
		t.Fatalf("Check rejected a user established by another middleware: %v", err)
	}
	user, _ := UserAs[*testUser](c)
	if user.ID != "9" {
		t.Errorf("Check replaced the established user with %+v", user)
	}
}

// A verified subject established elsewhere — the oauth2 bearer guard — must
// go through the same loader, so it produces the same type.
func TestCheckLoadsASubjectEstablishedElsewhere(t *testing.T) {
	a, ctx := newSessionAuth(t)
	a.userLoader, _ = loaderFor(&testUser{ID: "7", Email: "ada@example.com"})

	c := newCheckContext(ctx, nil)
	SetSubject(c, "7")

	if err := a.Check(c); err != nil {
		t.Fatalf("Check: %v", err)
	}
	if user, ok := UserAs[*testUser](c); !ok || user.Email != "ada@example.com" {
		t.Errorf("the subject was not loaded: %v, %v", user, ok)
	}
}

// A client-credentials token authenticates a caller with no user behind it.
// Protected must admit it while AuthUser stays nil — inventing a user for it
// was the old behaviour and it was a lie.
func TestAuthenticatedWithoutAUser(t *testing.T) {
	a, ctx := newSessionAuth(t)
	a.userLoader, _ = loaderFor()

	c := newCheckContext(ctx, nil)
	SetAuthenticated(c)

	if err := a.Check(c); err != nil {
		t.Fatalf("Check rejected an identity with no user: %v", err)
	}
	if AuthUser(c) != nil {
		t.Errorf("a user was invented: %v", AuthUser(c))
	}
	if !IsAuthenticated(c) {
		t.Error("IsAuthenticated reported false for a verified caller")
	}
}

func TestCheckStillRefusesWhenNoMechanismIsConfigured(t *testing.T) {
	if err := (&Auth{}).Check(newCheckContext(nil, nil)); err != ErrNoAuthMechanism {
		t.Fatalf("Check = %v, want ErrNoAuthMechanism", err)
	}
}

// The header was parsed by deleting the literal "bearer ", which missed the
// capitalised form every standards-compliant client sends.
func TestCheckParsesTheAuthorizationScheme(t *testing.T) {
	for _, tc := range []struct {
		name   string
		header string
		wantOK bool
	}{
		{"canonical Bearer", "Bearer ", true},
		{"lowercase bearer", "bearer ", true},
		{"odd casing", "BeArEr ", true},
		{"extra spacing", "Bearer   ", true},
		{"no scheme", "", false},
		{"wrong scheme", "Basic ", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			a := &Auth{jwtSecret: []byte("secret")}
			a.userLoader, _ = loaderFor(&testUser{ID: "7", Email: "ada@example.com"})

			request := httptest.NewRequest(http.MethodGet, "/", nil)
			if tc.header != "" {
				request.Header.Set("Authorization", tc.header+signedUserToken(t, a.jwtSecret, "7"))
			}

			err := a.Check(newCheckContext(nil, request))
			if tc.wantOK && err != nil {
				t.Fatalf("Check(%q) = %v, want success", tc.header, err)
			}
			if !tc.wantOK && err == nil {
				t.Fatalf("Check(%q) succeeded, want a failure", tc.header)
			}
		})
	}
}
