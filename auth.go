package auth

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/lemmego/api/app"
	"github.com/lemmego/api/config"
	"github.com/lemmego/api/session"
	"golang.org/x/crypto/bcrypt"
)

var (
	ErrUsernameMismatch    = errors.New("username mismatch")
	ErrPasswordMismatch    = errors.New("password mismatch")
	ErrJwtCouldNotBeSigned = errors.New("jwt could not be signed")
	ErrMissingUserID       = errors.New("auth: the user has no identifier")
)

type Opts struct {
	DisableSession bool
	JwtSecret      string
	JwtClaims      jwt.MapClaims
	JwtExpiration  time.Duration
	HomeRoute      string

	// UserLoader turns the id a verified credential carries into the
	// application's own user. Without it nothing can authenticate: see
	// UserLoader's own documentation for the contract it must honour.
	UserLoader UserLoader
}

type Provider struct {
	Opts *Opts
}

type Auth struct {
	sess           *session.Session
	userLoader     UserLoader
	jwtSecret      []byte
	jwtClaims      jwt.MapClaims
	homeRoute      string
	cookiePath     string
	cookieDomain   string
	cookieSecure   bool
	cookieHTTPOnly bool
	cookieSameSite http.SameSite
	jwtExpiration  time.Duration
}

type LoginResult struct {
	Err      error
	JwtToken string
	Cookie   *http.Cookie
}

// ErrNoAuthMechanism reports that neither a session nor a JWT secret is
// configured, so no request can be authenticated.
var ErrNoAuthMechanism = errors.New("auth: no authentication mechanism configured")

func New() *Auth {
	return &Auth{}
}

func (ap *Provider) Provide(a app.App) error {
	slog.Debug("Registering Auth")

	// &auth.Provider{} is the obvious way to write it, and it used to
	// nil-dereference on the next line. An unconfigured provider takes the
	// defaults, which is sessions on and no JWT.
	if ap.Opts == nil {
		ap.Opts = &Opts{}
	}

	var sess *session.Session
	var jwtSecret string
	if !ap.Opts.DisableSession {
		sess = app.Get[*session.Session](a)
	}
	if ap.Opts.JwtSecret != "" {
		jwtSecret = ap.Opts.JwtSecret
	}

	// Warn rather than refuse. Failing here would be circular: `lemmego run
	// appkey` boots this same provider stack to generate APP_KEY, which is
	// where the JWT secret usually comes from, so a hard error leaves a fresh
	// project unable to generate the key that would fix it. Check still fails
	// closed, so no request is authenticated in this state.
	if sess == nil && jwtSecret == "" {
		slog.Warn("auth: sessions are disabled and no JWT secret is set, so no request can be authenticated; " +
			"set JwtSecret (commonly from JWT_SECRET, falling back to APP_KEY) or leave sessions enabled")
	}

	// A credential now carries an id, so something has to turn that id back
	// into a user. Without a loader nothing authenticates.
	//
	// Warned rather than refused for the same circularity as above: a hard
	// error here would break `lemmego run appkey` on a project whose loader
	// needs a database it has not configured yet. An application already in
	// production, though, has a dead protected area, so say so louder there.
	if ap.Opts.UserLoader == nil {
		message := "auth: no UserLoader is configured, so no request can be authenticated; " +
			"set Opts.UserLoader to a function that fetches your user by id"
		if a.InProduction() {
			slog.Error(message)
		} else {
			slog.Warn(message)
		}
	}

	auth := &Auth{
		sess:           sess,
		userLoader:     ap.Opts.UserLoader,
		jwtSecret:      []byte(jwtSecret),
		homeRoute:      "/home",
		cookiePath:     "/",
		cookieDomain:   "",
		cookieSecure:   a.InProduction(),
		cookieHTTPOnly: true,
		cookieSameSite: http.SameSiteLaxMode,
		jwtExpiration:  24 * time.Hour,
		jwtClaims:      ap.Opts.JwtClaims,
	}

	if ap.Opts.HomeRoute != "" {
		auth.homeRoute = ap.Opts.HomeRoute
	}
	if ap.Opts.JwtExpiration > 0 {
		auth.jwtExpiration = ap.Opts.JwtExpiration
	}

	// Read cookie settings from session config
	if sessionCfg := a.Config().Get("session"); sessionCfg != nil {
		if sc, ok := sessionCfg.(config.M); ok {
			if v := sc.String("path", ""); v != "" {
				auth.cookiePath = v
			}
			if v := sc.String("domain", ""); v != "" {
				auth.cookieDomain = v
			}
			auth.cookieSecure = cookieSecureValue(a.InProduction(), sc)
			auth.cookieHTTPOnly = sc.Bool("http_only", true)
		}
	}

	a.AddService(auth)
	return nil
}

func Guest(c app.Context) error {
	return Get(c.App()).Guest(c)
}

func Protected(c app.Context) error {
	return Get(c.App()).Protected(c)
}

// OptionalAuth checks for an authenticated user without blocking the request.
// If a valid session or JWT token is found, the user is silently populated in
// the context. Unlike Protected/Guest this never blocks — it always allows the
// request to proceed. Useful for public routes that optionally show user info.
func OptionalAuth(c app.Context) error {
	_ = Get(c.App()).Check(c)
	return c.Next()
}

func Login(c app.Context, provider UserProvider, username, password string) *LoginResult {
	return Get(c.App()).Login(c, provider, username, password)
}

func Check(c app.Context) error {
	return Get(c.App()).Check(c)
}

func (p *Provider) WithConfig(config *Opts) *Provider {
	p.Opts = config
	return p
}

func (a *Auth) Guest(c app.Context) error {
	if err := a.Check(c); err == nil {
		// Redirect to home
		return c.Redirect(a.homeRoute)
	}
	return c.Next()
}

func (a *Auth) Protected(c app.Context) error {
	if err := a.Check(c); err != nil {
		// A store that could not answer is a server fault, not a rejected
		// credential. Flattening it into 401 would log everyone out over a
		// blip and then stampede the login page when they all retry.
		var storeDown *UserStoreUnavailableError
		if errors.As(err, &storeDown) {
			return err
		}
		// A misconfiguration is also not a rejected credential. 401 would
		// send an operator hunting for a bad password.
		if errors.Is(err, ErrNoUserLoader) || errors.Is(err, ErrNoAuthMechanism) {
			return c.InternalServerError(err)
		}
		return c.Unauthorized(fmt.Errorf("unauthorized: %w", err))
	}
	return c.Next()
}

// Check resolves the request's identity.
//
// Both mechanisms converge on an identifier, and the identifier is turned into
// a user by the application's loader. That convergence is the point: a handler
// sees the same concrete type whether the request arrived with a session
// cookie or a bearer token, because both ended in the same call.
func (a *Auth) Check(c app.Context) error {
	// Refuse when there is no mechanism to authenticate against. Returning nil
	// here would mean "authenticated", which made Protected admit anyone and
	// Guest turn everyone away — an app configured with DisableSession and no
	// JWT secret had a wide open protected area and an unreachable login page.
	if a.sess == nil && len(a.jwtSecret) == 0 {
		return ErrNoAuthMechanism
	}

	// A user another middleware has already established is authenticated.
	// This is what lets an external token verifier — an OAuth2 guard, a
	// signed-header gateway, a test harness — run ahead of Protected without
	// auth needing to know anything about it, and without the dependency
	// pointing back the other way.
	//
	// It is also the per-request memo: the loader runs once even when
	// Protected, a group guard and a handler all ask.
	if existing := c.Get(UserKey); existing != nil {
		return nil
	}
	// An identity with no user behind it — a client-credentials token.
	if marked, _ := c.Get(authenticatedKey).(bool); marked {
		return nil
	}
	// A failure is memoised too. Without this, three middlewares against a
	// database with a thirty-second timeout is ninety seconds of a held
	// connection on one dying request.
	if failed, ok := c.Get(loadErrorKey).(error); ok && failed != nil {
		return failed
	}

	id, ok := c.Get(UserIDKey).(string)
	if !ok || id == "" {
		resolved, err := a.subjectFromRequest(c)
		if err != nil {
			return err
		}
		id = resolved
		// Set before loading, so anything that only needs an id — a consent
		// screen, an audit line — works even when the load fails.
		c.Set(UserIDKey, id)
	}

	user, err := a.loadUser(c, id)
	if err != nil {
		c.Set(loadErrorKey, err)
		return err
	}
	c.Set(UserKey, user)
	return nil
}

// subjectFromRequest takes an identifier from whichever credential the request
// carries.
//
// Each configured mechanism gets a turn, and only the failure of all of them
// is a failure. This used to be two sequential ifs that both had to succeed:
// a session holding no user returned immediately, so with sessions enabled —
// the default — the bearer-token branch was unreachable code; and a session
// that did hold a user fell through into the JWT branch, which then rejected
// the request for carrying no token.
func (a *Auth) subjectFromRequest(c app.Context) (string, error) {
	var failures []error

	if a.sess != nil {
		if id, ok := a.sess.GetAs[string](c.RequestContext(), UserIDKey); ok && id != "" {
			return id, nil
		}
		failures = append(failures, errors.New("no user in session"))
	}

	if len(a.jwtSecret) > 0 {
		token, err := a.tokenFromRequest(c)
		if err != nil {
			failures = append(failures, err)
		} else if subject, err := a.jwtSubject(token); err != nil {
			failures = append(failures, err)
		} else {
			return subject, nil
		}
	}

	return "", errors.Join(failures...)
}

// loadUser calls the application's loader and normalises what comes back.
func (a *Auth) loadUser(c app.Context, id string) (any, error) {
	if a.userLoader == nil {
		return nil, ErrNoUserLoader
	}

	user, err := a.userLoader(c, id)

	switch {
	case errors.Is(err, ErrUserNotFound):
		return nil, a.revoke(c, err)

	case err != nil:
		// A cancelled request is the client hanging up, not the store
		// failing. Reporting it as an outage buries the real ones.
		if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
			return nil, fmt.Errorf("auth: loading the authenticated user: %w", err)
		}
		slog.Error("auth: the user store could not answer", "error", err, "user_id", id)
		return nil, unavailable(err)

	case isNilUser(user):
		// A loader that reports "no rows" as (nil, nil), or hands back a typed
		// nil pointer, must not authenticate anyone: a (*models.User)(nil) is
		// not nil as an any, so it would satisfy both the short-circuit above
		// and UserAs's assertion, and the first handler to read a field would
		// dereference nil.
		return nil, a.revoke(c, ErrUserNotFound)
	}

	return user, nil
}

// revoke destroys the credential behind an identity that no longer exists, so
// the next request is anonymous rather than another futile lookup of a dead id
// on every request until the session or token expires.
func (a *Auth) revoke(c app.Context, cause error) error {
	a.clearSession(c.RequestContext())
	c.SetCookie(&http.Cookie{
		Name:     "jwt",
		Value:    "",
		Path:     a.cookiePath,
		Domain:   a.cookieDomain,
		Secure:   a.cookieSecure,
		HttpOnly: a.cookieHTTPOnly,
		SameSite: a.cookieSameSite,
		MaxAge:   -1,
	})
	return cause
}

// tokenFromRequest reads the JWT from the jwt cookie, falling back to the
// Authorization header.
//
// The header is parsed as a scheme and a token rather than by trimming a
// literal prefix: the old form missed the capitalised "Bearer " that every
// standards-compliant client sends, and removed the substring wherever else
// it appeared.
func (a *Auth) tokenFromRequest(c app.Context) (string, error) {
	if cookie, err := c.Request().Cookie("jwt"); err == nil && cookie.Value != "" {
		return cookie.Value, nil
	}

	header := strings.TrimSpace(c.Header("Authorization"))
	if header == "" {
		return "", errors.New("no jwt cookie and no Authorization header")
	}
	scheme, token, found := strings.Cut(header, " ")
	if !found || !strings.EqualFold(scheme, "bearer") {
		return "", errors.New("Authorization header is not a Bearer token")
	}
	if token = strings.TrimSpace(token); token == "" {
		return "", errors.New("Bearer token is empty")
	}
	return token, nil
}

// jwtSubject verifies the token and returns its sub claim.
//
// The token carries nothing else about the user. It is signed, not encrypted,
// so anything embedded in it is readable by whoever holds it — which, before
// this, meant every field of the user row that was not tagged json:"-", and
// a stale copy of them at that.
func (a *Auth) jwtSubject(rawToken string) (string, error) {
	token, err := jwt.Parse(rawToken,
		func(*jwt.Token) (any, error) { return a.jwtSecret, nil },
		// Pin the algorithm through the library rather than checking inside
		// the key function: this rejects alg:none before the key is reached
		// at all.
		jwt.WithValidMethods([]string{jwt.SigningMethodHS256.Alg()}),
	)
	if err != nil {
		return "", err
	}
	if !token.Valid {
		return "", errors.New("invalid jwt")
	}

	subject, err := token.Claims.GetSubject()
	if err != nil || subject == "" {
		return "", errors.New("jwt has no sub claim")
	}
	return subject, nil
}

func (a *Auth) Login(c app.Context, userProvider UserProvider, username, password string) *LoginResult {
	loginResult := &LoginResult{}
	if userProvider == nil || userProvider.GetUsername() != username {
		loginResult.Err = ErrUsernameMismatch
		return loginResult
	}

	if err := bcrypt.CompareHashAndPassword([]byte(userProvider.GetPassword()), []byte(password)); err != nil {
		loginResult.Err = ErrPasswordMismatch
		return loginResult
	}

	// sub is the identity now, not decoration: it is the id the loader is
	// handed on every subsequent request. An empty one would mint a
	// credential whose very next request fails, so fail the login instead of
	// succeeding into a broken session.
	id := userProvider.GetID()
	if id == "" {
		loginResult.Err = ErrMissingUserID
		return loginResult
	}

	var token *jwt.Token

	if string(a.jwtSecret) != "" {
		claims := make(jwt.MapClaims, len(a.jwtClaims)+3)
		for key, value := range a.jwtClaims {
			claims[key] = value
		}

		// sub, iat and exp are applied last and unconditionally.
		//
		// The old loop applied them only when absent, so a configured
		// Opts.JwtClaims{"sub": …} overrode the real subject. That was
		// harmless while sub was decorative. It is privilege escalation now
		// that sub is what the loader looks up, so the precedence inverts.
		if _, taken := claims["sub"]; taken {
			slog.Warn("auth: Opts.JwtClaims sets sub, which identifies the user; it is being ignored")
		}
		now := time.Now()
		claims["sub"] = id
		claims["iat"] = now.Unix()
		claims["exp"] = now.Add(a.jwtExpirationOrDefault()).Unix()
		token = jwt.NewWithClaims(jwt.SigningMethodHS256, claims)

		tokenString, err := token.SignedString(a.jwtSecret)
		if err != nil {
			loginResult.Err = fmt.Errorf(ErrJwtCouldNotBeSigned.Error()+": %w", err)
			return loginResult
		}

		loginResult.JwtToken = tokenString
	}

	if a.sess != nil && c != nil {
		// Rotate the session id before the identity is written into it.
		// Without this an attacker who can plant a session cookie in the
		// victim's browser before they log in still holds a valid id
		// afterwards, and is authenticated as them — session fixation.
		// RenewToken issues a new id and carries the existing data across,
		// so the CSRF token in the session survives and the next request is
		// not rejected as expired.
		//
		// A failure here fails the login: completing it would leave the user
		// authenticated under the id the attacker chose.
		if err := a.renewSession(c.RequestContext()); err != nil {
			loginResult.Err = err
			return loginResult
		}
		// An identifier, not the object. Storing the object kept the type
		// across a restart but also wrote every exported field into the
		// session store — and gob ignores json:"-", so that included the
		// bcrypt hash.
		a.sess.Put(c.RequestContext(), UserIDKey, id)
	}

	// Seed the request memo, so the response handler renders the user it just
	// verified instead of reading the row straight back.
	if c != nil {
		c.Set(UserIDKey, id)
		c.Set(UserKey, userProvider)
	}

	if loginResult.JwtToken != "" && c != nil {
		c.SetCookie(&http.Cookie{
			Name:     "jwt",
			Value:    loginResult.JwtToken,
			Path:     a.cookiePath,
			Domain:   a.cookieDomain,
			Secure:   a.cookieSecure,
			HttpOnly: a.cookieHTTPOnly,
			SameSite: a.cookieSameSite,
		})
	}

	return loginResult
}

// renewSession rotates the session id, keeping the data in it. It is the
// session-fixation defence: an attacker who plants a session cookie in the
// victim's browser before they log in must not still hold a valid id after.
func (a *Auth) renewSession(ctx context.Context) error {
	if a.sess == nil {
		return nil
	}
	if err := a.sess.RenewToken(ctx); err != nil {
		return fmt.Errorf("renewing the session on login: %w", err)
	}
	return nil
}

// clearSession destroys the session behind a logout, so the id it was
// authenticated under stops being valid and nothing outlives the logged-in
// user. Anything written afterwards lands in a fresh session.
func (a *Auth) clearSession(ctx context.Context) {
	if a.sess == nil {
		return
	}
	err := a.sess.Destroy(ctx)
	if err == nil {
		return
	}

	// The store refused to delete the record, so the data is still there and
	// the user would stay logged in. Remove the identity and rotate the id
	// explicitly rather than report a logout that did not happen.
	slog.Error("auth: could not destroy the session on logout", "error", err)
	a.sess.Pop(ctx, UserIDKey)
	if err := a.sess.RenewToken(ctx); err != nil {
		slog.Error("auth: could not rotate the session id on logout", "error", err)
	}
}

func (a *Auth) jwtExpirationOrDefault() time.Duration {
	if a.jwtExpiration > 0 {
		return a.jwtExpiration
	}
	return 24 * time.Hour
}

func cookieSecureValue(production bool, settings config.M) bool {
	secure := production
	if value, ok := settings["secure"]; ok {
		switch value := value.(type) {
		case bool:
			secure = value
		case string:
			if parsed, err := strconv.ParseBool(value); err == nil {
				secure = parsed
			}
		}
	}
	return secure
}

// Logout clears the user's session and removes the JWT cookie.
//
// The whole session is destroyed rather than just the user key, so the id the
// session was authenticated under stops being valid and no other data outlives
// the logged-in user. Anything written afterwards — a flash message on the way
// to the login page, say — lands in a fresh session.
func (a *Auth) Logout(c app.Context) {
	a.clearSession(c.RequestContext())
	c.SetCookie(&http.Cookie{
		Name:     "jwt",
		Value:    "",
		Path:     a.cookiePath,
		Domain:   a.cookieDomain,
		Secure:   a.cookieSecure,
		HttpOnly: a.cookieHTTPOnly,
		SameSite: a.cookieSameSite,
		MaxAge:   -1,
	})
}

// Logout clears the user's session and removes the JWT cookie.
func Logout(c app.Context) {
	Get(c.App()).Logout(c)
}

func Get(a app.App) *Auth {
	return app.Get[*Auth](a)
}
