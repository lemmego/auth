package auth

import (
	"context"
	"errors"
	"fmt"
	"github.com/lemmego/api/session"
	"log/slog"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"

	"github.com/lemmego/api/app"
	"github.com/lemmego/api/db"
	"github.com/lemmego/api/shared"
	"github.com/romsar/gonertia"

	"dario.cat/mergo"

	"github.com/golang-jwt/jwt/v4"
	"golang.org/x/crypto/bcrypt"
	"golang.org/x/oauth2"
)

var (
	authInstance *Auth
	mu           sync.RWMutex

	ErrInvalidCreds   = errors.New("invalid credentials")
	ErrUserNotFound   = errors.New("user not found")
	ErrLoginFailed    = errors.New("login failed")
	ErrNoStrategy     = errors.New("no strategy provided: either the session manager or the token config must be provided")
	ErrNoSecret       = errors.New("no secret provided: the JWT_SECRET env variable must be provided")
	ErrNoSession      = errors.New("no session provided: the session manager must be provided")
	ErrNoUserSession  = errors.New("user session doesn't exists")
	ErrInvalidJwtSign = errors.New("invalid jwt signature")
)

type Actor interface {
	Id() interface{}
	GetUsername() string
	GetPassword() string
}

type AuthUser struct {
	ID       interface{} `json:"id"`
	Username string      `json:"username"`
}

type CredUser struct {
	ID       interface{} `json:"id"`
	Username string      `json:"username"`
	Password string      `json:"password"`
}

type Credentials struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

// type GenericUser struct {
// 	FirstName string `json:"first_name"`
// 	LastName  string `json:"last_name"`
// 	Username  string `json:"username"`
// 	Password  string `json:"password"`
// }

type Options struct {
	Router            app.Router
	DB                *db.Connection
	Session           *session.Session
	TokenConfig       *TokenConfig
	GoogleOAuthConfig *oauth2.Config
	CustomViewMap     map[string]string
	HomeRoute         string
}

type Auth struct {
	Opts     *Options
	AuthUser Actor
}

type OptFunc func(opts *Options)

type TokenConfig struct {
	Claims jwt.RegisteredClaims
}

func Get() *Auth {
	mu.RLock()
	defer mu.RUnlock()
	return authInstance
}

func Set(instance *Auth) {
	mu.Lock()
	defer mu.Unlock()
	authInstance = instance
}

func DefaultOptions() *Options {
	return &Options{
		HomeRoute: "/home",
	}
}

func WithSessionManager(session *session.Session) OptFunc {
	return func(opts *Options) {
		opts.Session = session
	}
}

func WithTokenConfig(tokenConfig *TokenConfig) OptFunc {
	return func(opts *Options) {
		opts.TokenConfig = tokenConfig
	}
}

func New(opts ...OptFunc) *Auth {
	o := DefaultOptions()

	for _, opt := range opts {
		opt(o)
	}

	//if o.TokenConfig == nil && o.Session == nil {
	//	panic(ErrNoStrategy)
	//}

	if o.TokenConfig != nil && os.Getenv("JWT_SECRET") == "" {
		panic(ErrNoSecret)
	}

	return &Auth{o, nil}
}

func (authn *Auth) PersistUserSession(ctx context.Context, user interface{}) {
	if authn.Opts.Session != nil {
		authn.Opts.Session.Put(ctx, "user", user)
	}
}

func (authn *Auth) Login(ctx context.Context, a Actor, username string, password string) (token string, err error) {
	// If the username and password are empty, return an error
	if a.GetUsername() == "" && a.GetPassword() == "" {
		return "", ErrInvalidCreds
	}

	// If the username doesn't match the one provided, return an error
	if a.GetUsername() != username {
		return "", ErrUserNotFound
	}

	// If the password doesn't match the one provided, return an error
	if err := bcrypt.CompareHashAndPassword([]byte(a.GetPassword()), []byte(password)); a.GetUsername() != "" && a.GetPassword() != "" && err != nil {
		return "", ErrInvalidCreds
	}

	// If the session manager is provided, store the user in the session
	if authn.Opts.Session != nil {
		authn.Opts.Session.Put(ctx, "user", a)
		authn.Opts.Session.Put(ctx, "userId", a.Id())
		token = ""
	}

	// If the token config is provided, generate a token
	if authn.Opts.TokenConfig != nil {
		mergo.Merge(&authn.Opts.TokenConfig.Claims, jwt.RegisteredClaims{
			Subject: strconv.Itoa(int(a.Id().(uint))),
		})

		claims := jwt.NewWithClaims(jwt.SigningMethodHS256, authn.Opts.TokenConfig.Claims)

		token, err = claims.SignedString([]byte(os.Getenv("JWT_SECRET")))
	}

	// Return the token and error
	return token, err
}

func (authn *Auth) ForceLogin(ctx context.Context, a Actor) (token string, err error) {
	if a.GetUsername() != "" && a.GetPassword() != "" {
		if authn.Opts.Session != nil {
			authn.Opts.Session.Put(ctx, "userId", a.Id())
		}
		if authn.Opts.TokenConfig != nil {
			mergo.Merge(&authn.Opts.TokenConfig.Claims, jwt.RegisteredClaims{
				Subject: strconv.Itoa(int(a.Id().(uint))),
			})
			claims := jwt.NewWithClaims(jwt.SigningMethodHS256, authn.Opts.TokenConfig.Claims)

			token, err = claims.SignedString([]byte(os.Getenv("JWT_SECRET")))
		}
	} else {
		return "", ErrLoginFailed
	}

	return token, err
}

func (authn *Auth) Check(r *http.Request) error {
	var user Actor
	if authn.Opts.Session != nil {
		if exists := authn.Opts.Session.Exists(r.Context(), "userId"); exists {
			user = authn.Opts.Session.Get(r.Context(), "user").(Actor)
			authn.AuthUser = user
			return nil
		} else {
			return ErrNoUserSession
		}
	}

	if authn.Opts.TokenConfig != nil {
		jwtToken := ""
		jwtCookie, err := r.Cookie("jwt")
		if err == nil {
			jwtToken = strings.Replace(jwtCookie.Value, "jwt=", "", -1)
		} else {
			jwtToken = strings.Replace(r.Header.Get("Authorization"), "bearer ", "", -1)
		}
		if jwtToken == "" {
			return errors.New("jwt cookie not found")
		}
		token, err := jwt.Parse(jwtToken, func(token *jwt.Token) (interface{}, error) {
			// Don't forget to validate the alg is what you expect:
			if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
				return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
			}

			// hmacSampleSecret is a []byte containing your secret, e.g. []byte("my_secret_key")
			return []byte(os.Getenv("JWT_SECRET")), nil
		})

		if err != nil {
			return err
		}

		if _, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
			//user.ID = claims["sub"].(string)
			//user.Username = claims["username"].(string)
		}

		authn.AuthUser = user
	}
	return errors.New("could not parse jwt")
}

// Guard the route with the auth middleware
func (authn *Auth) Guard(c *app.Context) error {
	if err := authn.Check(c.Request()); err != nil {
		return c.Redirect("/login")
	} else {
		c.Set("user", authn.AuthUser)
		return c.Next()
	}
}

// Guest middleware disallows authenticated users from accessing a route
func (authn *Auth) Guest(c *app.Context) error {
	if err := authn.Check(c.Request()); err == nil {
		return c.Redirect(authn.Opts.HomeRoute)
	} else {
		return c.Next()
	}
}

// Tenant middleware resolves the tenant model from the request
func (authn *Auth) Tenant(c *app.Context) error {
	// Check if "tenant" header is set
	tenant := c.GetHeader("tenant")

	if tenant == "" && (c.WantsJSON() || gonertia.IsInertiaRequest(c.Request())) {
		var data map[string]any
		err := c.DecodeJSON(&data)

		if err != nil {
			return err
		}

		if val, ok := data["org_username"].(string); ok {
			tenant = val
		}
	}

	if tenant == "" && c.HasFormURLEncodedRequest() || c.HasMultiPartRequest() {
		tenant = c.Request().FormValue("org_username")
	}

	if tenant == "" {
		// See if subdomain is set and split the host by . and
		// treat the first part as the tenant if it's not "www"
		parts := strings.Split(c.Request().Host, ".")
		if len(parts) > 1 && parts[0] != "www" {
			tenant = parts[0]
		}
	}

	type Org struct {
		ID          uint
		OrgUsername string
	}

	model := &Org{}

	var count int64
	authn.Opts.DB.DB().First(model, "org_username = ?", tenant).Count(&count)

	if count > 0 {
		slog.Info("Tenant ID", "id", model.ID)
		c.Set("org_id", model.ID)
	} else {
		if c.WantsJSON() && !gonertia.IsInertiaRequest(c.Request()) {
			return c.Status(http.StatusNotFound).JSON(app.M{"message": "Org not found"})
		}

		return c.WithErrors(shared.ValidationErrors{"org_username": []string{"Org not found"}}).Back()
	}
	return c.Next()
}
