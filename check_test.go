package auth

import (
	"context"
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
	ctx    context.Context
	req    *http.Request
	values map[string]any
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

// Login writes the JWT cookie; the tests here only care about the token.
func (c *checkContext) SetCookie(*http.Cookie) app.CookieGetSetter { return nil }

func signedUserToken(t *testing.T, secret []byte) string {
	t.Helper()
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"user": `{"id":7,"email":"user@example.com"}`,
		"exp":  time.Now().Add(time.Hour).Unix(),
	})
	raw, err := token.SignedString(secret)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

// Check used to run the session and the JWT branches in sequence, and both
// had to succeed. A session holding no user returned before the JWT branch,
// so with sessions enabled — the default — a bearer token could never
// authenticate anything.
func TestCheckFallsBackToBearerTokenWhenTheSessionIsEmpty(t *testing.T) {
	a, ctx := newSessionAuth(t)
	a.jwtSecret = []byte("secret")

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Authorization", "Bearer "+signedUserToken(t, a.jwtSecret))
	c := newCheckContext(ctx, req)

	if err := a.Check(c); err != nil {
		t.Fatalf("Check rejected a valid bearer token because the session was empty: %v", err)
	}
	user, ok := c.Get(UserKey).(map[string]any)
	if !ok {
		t.Fatalf("Check set %T as the user, want the decoded claims", c.Get(UserKey))
	}
	if user["email"] != "user@example.com" {
		t.Errorf("user claim = %v", user)
	}
}

// The mirror image: a session that does hold a user used to fall through into
// the JWT branch, which then rejected the request for carrying no token. So
// configuring a JWT secret alongside sessions broke session login outright.
func TestCheckAcceptsASessionUserWhenAJWTSecretIsAlsoConfigured(t *testing.T) {
	a, ctx := newSessionAuth(t)
	a.jwtSecret = []byte("secret")
	a.sess.Put(ctx, UserKey, &User{ID: 3, Email: "in-session@example.com"})

	c := newCheckContext(ctx, nil)
	if err := a.Check(c); err != nil {
		t.Fatalf("Check rejected a logged-in session because no JWT was present: %v", err)
	}
	user, ok := c.Get(UserKey).(*User)
	if !ok {
		t.Fatalf("Check set %T as the user, want the session's own type", c.Get(UserKey))
	}
	if user.Email != "in-session@example.com" {
		t.Errorf("user = %+v", user)
	}
}

// A user another middleware already established is authenticated. This is the
// seam an external token verifier hangs off without auth depending on it.
func TestCheckHonoursAPreEstablishedUser(t *testing.T) {
	a, ctx := newSessionAuth(t)
	a.jwtSecret = []byte("secret")

	c := newCheckContext(ctx, nil)
	c.Set(UserKey, map[string]any{"id": "from-another-middleware"})

	if err := a.Check(c); err != nil {
		t.Fatalf("Check rejected a user established by another middleware: %v", err)
	}
	if got := c.Get(UserKey).(map[string]any)["id"]; got != "from-another-middleware" {
		t.Errorf("Check replaced the established user with %v", got)
	}
}

// The header was parsed by deleting the literal "bearer ", which missed the
// capitalised form every standards-compliant client sends and mangled any
// token containing that substring.
func TestCheckParsesTheAuthorizationScheme(t *testing.T) {
	secret := []byte("secret")
	token := signedUserToken(t, secret)

	for _, tc := range []struct {
		name   string
		header string
		wantOK bool
	}{
		{"canonical Bearer", "Bearer " + token, true},
		{"lowercase bearer", "bearer " + token, true},
		{"odd casing", "BeArEr " + token, true},
		{"extra spacing", "Bearer   " + token, true},
		{"no scheme", token, false},
		{"wrong scheme", "Basic " + token, false},
		{"empty token", "Bearer ", false},
		{"empty header", "", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			a := &Auth{jwtSecret: secret}
			req := httptest.NewRequest(http.MethodGet, "/", nil)
			if tc.header != "" {
				req.Header.Set("Authorization", tc.header)
			}

			err := a.Check(newCheckContext(nil, req))
			if tc.wantOK && err != nil {
				t.Fatalf("Check(%q) = %v, want success", tc.header, err)
			}
			if !tc.wantOK && err == nil {
				t.Fatalf("Check(%q) succeeded, want a failure", tc.header)
			}
		})
	}
}

// Opts.JwtClaims was declared, documented and never read: Provide built the
// Auth without it, so every custom claim an application configured was
// silently dropped and only tests that constructed &Auth{} directly ever
// exercised the field.
func TestProvideCarriesConfiguredJWTClaims(t *testing.T) {
	a := app.Configure()
	provider := &Provider{Opts: &Opts{
		DisableSession: true,
		JwtSecret:      "secret",
		JwtClaims:      jwt.MapClaims{"iss": "example.com", "role": "admin"},
	}}
	if err := provider.Provide(a); err != nil {
		t.Fatal(err)
	}

	auth, ok := app.Lookup[*Auth](a)
	if !ok {
		t.Fatal("Provide registered no *Auth")
	}
	if auth.jwtClaims == nil {
		t.Fatal("Provide dropped Opts.JwtClaims")
	}
	if auth.jwtClaims["iss"] != "example.com" || auth.jwtClaims["role"] != "admin" {
		t.Fatalf("jwtClaims = %v", auth.jwtClaims)
	}

	// The claims must actually reach an issued token, not merely be stored.
	user := testLoginUser(t)
	result := auth.Login(newCheckContext(context.Background(), nil), user, user.Email, "password")
	if result.Err != nil {
		t.Fatalf("login failed: %v", result.Err)
	}
	parsed, err := jwt.Parse(result.JwtToken, func(*jwt.Token) (any, error) { return auth.jwtSecret, nil })
	if err != nil {
		t.Fatal(err)
	}
	claims := parsed.Claims.(jwt.MapClaims)
	if claims["iss"] != "example.com" || claims["role"] != "admin" {
		t.Errorf("issued token claims = %v; the configured claims did not reach it", claims)
	}
}
