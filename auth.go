package auth

import (
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

	if a.sess != nil {
		if user := a.sess.Get(c.RequestContext(), UserKey); user == nil {
			return errors.New("user not found in session")
		} else {
			c.Set(UserKey, user)
		}
	}

	if string(a.jwtSecret) != "" {
		jwtToken := ""
		jwtCookie, err := c.Request().Cookie("jwt")
		if err == nil {
			jwtToken = strings.Replace(jwtCookie.Value, "jwt=", "", -1)
		} else {
			jwtToken = strings.Replace(c.Header("Authorization"), "bearer ", "", -1)
		}
		if jwtToken == "" {
			return errors.New("jwt cookie not found")
		}

		authUser, err := a.jwtUser(jwtToken)
		if err != nil {
			return err
		}
		c.Set(UserKey, authUser)
		return nil
	}

	return nil
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
func (a *Auth) Logout(c app.Context) {
	if a.sess != nil {
		a.sess.Pop(c.RequestContext(), UserKey)
	}
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
