package auth

import (
	"testing"
	"time"

	"errors"
	"github.com/golang-jwt/jwt/v5"
	"github.com/lemmego/api/config"
	"golang.org/x/crypto/bcrypt"
)

func TestLoginRequiresHashedPassword(t *testing.T) {
	password := "correct horse battery staple"
	hashed, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		t.Fatal(err)
	}

	a := &Auth{}
	user := &User{ID: 1, Email: "user@example.com", Password: string(hashed)}
	if result := a.Login(nil, user, user.Email, password); result.Err != nil {
		t.Fatalf("expected hashed password to authenticate: %v", result.Err)
	}
	if result := a.Login(nil, &User{Email: user.Email, Password: password}, user.Email, password); result.Err != ErrPasswordMismatch {
		t.Fatalf("expected plaintext password to be rejected, got %v", result.Err)
	}
}

func TestJWTSubjectRejectsMalformedToken(t *testing.T) {
	a := &Auth{jwtSecret: []byte("secret")}

	if _, err := a.jwtSubject("not-a-jwt"); err == nil {
		t.Fatal("expected malformed token to fail")
	}
}

func TestJWTSubjectRejectsExpiredToken(t *testing.T) {
	a := &Auth{jwtSecret: []byte("secret")}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"sub": "1",
		"exp": time.Now().Add(-time.Minute).Unix(),
	})
	rawToken, err := token.SignedString(a.jwtSecret)
	if err != nil {
		t.Fatal(err)
	}

	if _, err := a.jwtSubject(rawToken); err == nil {
		t.Fatal("expected expired token to fail")
	}
}

// sub is the identity now. A token without one names nobody and cannot be
// resolved, so it must be refused rather than treated as anonymous.
func TestJWTSubjectRejectsAMissingSubject(t *testing.T) {
	a := &Auth{jwtSecret: []byte("secret")}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{"role": "admin"})
	rawToken, err := token.SignedString(a.jwtSecret)
	if err != nil {
		t.Fatal(err)
	}

	if _, err := a.jwtSubject(rawToken); err == nil {
		t.Fatal("expected a token with no sub claim to fail")
	}
}

// A token signed with anything but the pinned algorithm must be refused. The
// library rejects alg:none before the key function is reached.
func TestJWTSubjectRejectsAlgNone(t *testing.T) {
	a := &Auth{jwtSecret: []byte("secret")}
	token := jwt.NewWithClaims(jwt.SigningMethodNone, jwt.MapClaims{
		"sub": "1",
		"exp": time.Now().Add(time.Hour).Unix(),
	})
	rawToken, err := token.SignedString(jwt.UnsafeAllowNoneSignatureType)
	if err != nil {
		t.Fatal(err)
	}

	if _, err := a.jwtSubject(rawToken); err == nil {
		t.Fatal("a token with alg:none was accepted")
	}
}

func TestLoginAddsDefaultExpiryClaimsWithoutMutatingConfiguredClaims(t *testing.T) {
	claims := jwt.MapClaims{"role": "admin"}
	a := &Auth{jwtSecret: []byte("secret"), jwtClaims: claims}
	user := testLoginUser(t)
	started := time.Now().Unix()

	result := a.Login(nil, user, user.Email, "password")
	if result.Err != nil {
		t.Fatal(result.Err)
	}
	parsed, err := jwt.Parse(result.JwtToken, func(token *jwt.Token) (any, error) {
		return a.jwtSecret, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	parsedClaims := parsed.Claims.(jwt.MapClaims)
	exp, err := parsedClaims.GetExpirationTime()
	if err != nil {
		t.Fatal(err)
	}
	iat, err := parsedClaims.GetIssuedAt()
	if err != nil {
		t.Fatal(err)
	}
	if iat.Unix() < started || iat.Unix() > time.Now().Unix() {
		t.Fatalf("unexpected iat: %d", iat.Unix())
	}
	if got := exp.Unix() - iat.Unix(); got != int64((24 * time.Hour).Seconds()) {
		t.Fatalf("expected 24h expiry, got %d seconds", got)
	}
	if _, ok := claims["exp"]; ok {
		t.Fatal("login mutated configured claims")
	}
	if _, ok := claims["iat"]; ok {
		t.Fatal("login mutated configured claims")
	}
}

func TestLoginUsesCustomJWTExpiration(t *testing.T) {
	a := &Auth{jwtSecret: []byte("secret"), jwtExpiration: 90 * time.Minute}
	result := a.Login(nil, testLoginUser(t), "user@example.com", "password")
	if result.Err != nil {
		t.Fatal(result.Err)
	}
	parsed, err := jwt.Parse(result.JwtToken, func(token *jwt.Token) (any, error) {
		return a.jwtSecret, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	claims := parsed.Claims.(jwt.MapClaims)
	exp, _ := claims.GetExpirationTime()
	iat, _ := claims.GetIssuedAt()
	if got := exp.Unix() - iat.Unix(); got != int64((90 * time.Minute).Seconds()) {
		t.Fatalf("expected 90m expiry, got %d seconds", got)
	}
}

func TestCookieSecureValue(t *testing.T) {
	if cookieSecureValue(false, config.M{}) {
		t.Fatal("development cookies should not be secure by default")
	}
	if !cookieSecureValue(true, config.M{}) {
		t.Fatal("production cookies should be secure by default")
	}
	if cookieSecureValue(true, config.M{"secure": false}) {
		t.Fatal("explicit secure=false should override production default")
	}
	if !cookieSecureValue(false, config.M{"secure": true}) {
		t.Fatal("explicit secure=true should override development default")
	}
}

func testLoginUser(t *testing.T) *User {
	t.Helper()
	hashed, err := bcrypt.GenerateFromPassword([]byte("password"), bcrypt.MinCost)
	if err != nil {
		t.Fatal(err)
	}
	return &User{ID: 1, Email: "user@example.com", Password: string(hashed)}
}

// With sessions disabled and no JWT secret there is nothing to authenticate
// against. Check must refuse rather than return nil, which previously meant
// "authenticated": Protected admitted anyone and Guest turned everyone away,
// so a scaffolded app had an open admin area and an unreachable login page.
func TestCheckFailsClosedWithoutAnyMechanism(t *testing.T) {
	a := &Auth{} // no session, no jwt secret

	err := a.Check(nil)
	if err == nil {
		t.Fatal("Check must not report success when nothing can be verified")
	}
	if !errors.Is(err, ErrNoAuthMechanism) {
		t.Fatalf("expected ErrNoAuthMechanism, got %v", err)
	}
}

// &auth.Provider{} is how anyone would first write it, and it used to
// nil-dereference reading Opts.DisableSession.
func TestProvideWithoutOptsDoesNotPanic(t *testing.T) {
	provider := &Provider{}

	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("Provide() panicked on a nil Opts: %v", r)
		}
	}()

	// Sessions are on by default, so this reaches app.Get for the session and
	// fails there rather than on the nil Opts. Either outcome proves the nil
	// guard ran; what matters is which panic we do not get.
	func() {
		defer func() { _ = recover() }()
		_ = provider.Provide(nil)
	}()

	if provider.Opts == nil {
		t.Error("Provide() left Opts nil")
	}
}
