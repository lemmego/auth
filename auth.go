package auth

import (
	"context"
	"encoding/gob"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"

	"dario.cat/mergo"
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
	HomeRoute      string
}

type Provider struct {
	Opts *Opts
}

type Auth struct {
	sess             *session.Session
	jwtSecret        []byte
	jwtClaims        jwt.MapClaims
	homeRoute        string
	cookiePath       string
	cookieDomain     string
	cookieSecure     bool
	cookieHTTPOnly   bool
	cookieSameSite   http.SameSite
}

type LoginResult struct {
	Err      error
	JwtToken string
	Cookie   *http.Cookie
}

func New() *Auth {
	return &Auth{}
}

func (ap *Provider) Provide(a app.App) error {
	fmt.Println("Registering Auth")
	var sess *session.Session
	var jwtSecret string
	if !ap.Opts.DisableSession {
		sess = app.Get[*session.Session](a)
	}
	if ap.Opts.JwtSecret != "" {
		jwtSecret = ap.Opts.JwtSecret
	}

	auth := &Auth{
		sess:             sess,
		jwtSecret:        []byte(jwtSecret),
		homeRoute:        "/home",
		cookiePath:       "/",
		cookieDomain:     "",
		cookieSecure:     false,
		cookieHTTPOnly:   true,
		cookieSameSite:   http.SameSiteLaxMode,
	}

	if ap.Opts.HomeRoute != "" {
		auth.homeRoute = ap.Opts.HomeRoute
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
			auth.cookieSecure = sc.Bool("secure", false)
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

		token, err := jwt.Parse(jwtToken, func(token *jwt.Token) (any, error) {
			if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
				return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
			}

			return a.jwtSecret, nil
		})

		if err != nil {
			return err
		}

		if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
			var authUser map[string]any
			if err = json.Unmarshal([]byte(claims["user"].(string)), &authUser); err != nil {
				return err
			}
			c.Set(UserKey, authUser)
			return nil
		}
	}

	return nil
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
		if a.jwtClaims != nil {
			err = mergo.Merge(a.jwtClaims, defaultClaims)

			if err != nil {
				loginResult.Err = errors.New("provided claims could not be merged with the default claims")
				return loginResult
			}
			token = jwt.NewWithClaims(jwt.SigningMethodHS256, a.jwtClaims)
		} else {
			token = jwt.NewWithClaims(jwt.SigningMethodHS256, defaultClaims)
		}

		tokenString, err := token.SignedString(a.jwtSecret)
		if err != nil {
			loginResult.Err = fmt.Errorf(ErrJwtCouldNotBeSigned.Error()+": %w", err)
			return loginResult
		}

		loginResult.JwtToken = tokenString
	}

	if a.sess != nil {
		a.sess.Put(c.RequestContext(), UserKey, userProvider)
	}

	if loginResult.JwtToken != "" {
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

func (a *Auth) Logout(ctx context.Context) {
	if a.sess != nil {
		a.sess.Pop(ctx, UserKey)
	}
}

func Get(a app.App) *Auth {
	return app.Get[*Auth](a)
}
