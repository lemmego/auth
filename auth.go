package auth

import (
	"context"
	"encoding/gob"
	"encoding/json"
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
)

func init() {
	gob.Register(&User{})
}

const UserKey = "user"

type Opts struct {
	DisableSession bool
	JwtSecret      string
	JwtClaims      jwt.MapClaims
	JwtExpiration  time.Duration
	HomeRoute      string
}

type Provider struct {
	Opts *Opts
}

type Auth struct {
	sess           *session.Session
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

	auth := &Auth{
		sess:           sess,
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

func AuthUser(c app.Context) any {
	return c.Get(UserKey)
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
		return c.Unauthorized(fmt.Errorf("unauthorized: %w", err))
	}
	return c.Next()
}

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
	if existing := c.Get(UserKey); existing != nil {
		return nil
	}

	// Each configured mechanism gets a turn, and only the failure of all of
	// them is a failure to authenticate.
	//
	// This used to be two sequential ifs that both had to succeed. A session
	// holding no user returned immediately, so with sessions enabled — the
	// default — the bearer-token branch below was unreachable code. And a
	// session that did hold a user fell through into the JWT branch, which
	// then rejected the request for having no token. Configuring a JWT secret
	// alongside sessions therefore broke session login outright.
	var failures []error

	if a.sess != nil {
		if user := a.sess.Get(c.RequestContext(), UserKey); user != nil {
			c.Set(UserKey, user)
			return nil
		}
		failures = append(failures, errors.New("no user in session"))
	}

	if len(a.jwtSecret) > 0 {
		token, err := a.tokenFromRequest(c)
		if err != nil {
			failures = append(failures, err)
		} else if authUser, err := a.jwtUser(token); err != nil {
			failures = append(failures, err)
		} else {
			c.Set(UserKey, authUser)
			return nil
		}
	}

	return errors.Join(failures...)
}

// tokenFromRequest reads the JWT from the jwt cookie, falling back to the
// Authorization header.
//
// The header is parsed as a scheme and a token rather than by trimming a
// literal prefix. The old code did strings.Replace(header, "bearer ", "", -1),
// which missed the "Bearer " every standards-compliant client actually sends,
// and removed the substring wherever else it appeared in the token.
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

func (a *Auth) jwtUser(rawToken string) (map[string]any, error) {
	token, err := jwt.Parse(rawToken, func(token *jwt.Token) (any, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}

		return a.jwtSecret, nil
	})
	if err != nil {
		return nil, err
	}
	if !token.Valid {
		return nil, errors.New("invalid jwt")
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return nil, errors.New("invalid jwt claims")
	}
	encodedUser, ok := claims["user"].(string)
	if !ok || encodedUser == "" {
		return nil, errors.New("invalid jwt user claim")
	}

	var authUser map[string]any
	if err := json.Unmarshal([]byte(encodedUser), &authUser); err != nil {
		return nil, err
	}
	return authUser, nil
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

	var token *jwt.Token
	userSubEncoded, err := json.Marshal(userProvider)
	if err != nil {
		loginResult.Err = err
		return loginResult
	}

	defaultClaims := jwt.MapClaims{
		"user": string(userSubEncoded),
		"sub":  userProvider.GetID() + "|" + userProvider.GetUsername(),
	}

	if string(a.jwtSecret) != "" {
		claims := make(jwt.MapClaims, len(defaultClaims)+len(a.jwtClaims)+2)
		if a.jwtClaims != nil {
			for key, value := range a.jwtClaims {
				claims[key] = value
			}
		}
		for key, value := range defaultClaims {
			if _, exists := claims[key]; !exists {
				claims[key] = value
			}
		}
		now := time.Now()
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
		a.sess.Put(c.RequestContext(), UserKey, userProvider)
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
	a.sess.Pop(ctx, UserKey)
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
