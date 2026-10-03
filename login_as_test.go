package auth

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

// passwordlessUser is an account created by a social callback: no password
// was ever set, so GetPassword returns the empty string. UserProvider requires
// the method, which is why such an account could not be logged in through
// Login at all — bcrypt.CompareHashAndPassword against "" always fails.
type passwordlessUser struct {
	id    string
	email string
}

func (u *passwordlessUser) GetID() string       { return u.id }
func (u *passwordlessUser) GetUsername() string { return u.email }
func (u *passwordlessUser) GetPassword() string { return "" }

// The case LoginAs exists for. A GitHub-only account has no password, so
// Login cannot admit it; LoginAs can, because the identity was established by
// the provider callback rather than by a password.
func TestLoginAsAdmitsAnAccountWithNoPassword(t *testing.T) {
	a, ctx := newSessionAuth(t)
	a.jwtSecret = []byte("secret")
	user := &passwordlessUser{id: "7", email: "ada@example.com"}
	a.userLoader, _ = loaderFor(&testUser{ID: "7", Email: "ada@example.com"})

	c := newCheckContext(ctx, httptest.NewRequest(http.MethodPost, "/auth/github/callback", nil))

	result := a.LoginAs(c, user)
	if result.Err != nil {
		t.Fatalf("LoginAs: %v", result.Err)
	}
	if result.JwtToken == "" {
		t.Error("LoginAs minted no token")
	}
	if got := a.sess.GetString(ctx, UserIDKey); got != "7" {
		t.Errorf("session subject = %q, want 7", got)
	}

	// For contrast: the password path cannot admit this user, which is the
	// whole reason LoginAs is needed.
	if err := a.Login(c, user, "ada@example.com", "").Err; err == nil {
		t.Error("Login admitted an account with no password; it must compare a hash")
	}
}

// LoginAs must do everything Login does after the password check, or a social
// login would get a weaker session than a password login.
func TestLoginAsRotatesTheSessionAgainstFixation(t *testing.T) {
	a, ctx := newSessionAuth(t)
	a.userLoader, _ = loaderFor(&testUser{ID: "7", Email: "ada@example.com"})

	// Give the session an id before logging in, as an attacker who planted a
	// cookie would have.
	a.sess.Put(ctx, "planted", "value")
	before := a.sess.Token(ctx)

	c := newCheckContext(ctx, nil)
	if result := a.LoginAs(c, &passwordlessUser{id: "7", email: "ada@example.com"}); result.Err != nil {
		t.Fatal(result.Err)
	}

	if after := a.sess.Token(ctx); after == before && before != "" {
		t.Error("LoginAs did not rotate the session id, so a planted cookie stays valid")
	}
}

// Login still verifies the password — splitting LoginAs out must not have
// opened a hole in it.
func TestLoginStillComparesThePassword(t *testing.T) {
	a, ctx := newSessionAuth(t)
	a.userLoader, _ = loaderFor()
	c := newCheckContext(ctx, nil)

	user := &testUser{ID: "7", Email: "ada@example.com"}

	if err := a.Login(c, user, "ada@example.com", "anything").Err; err != ErrPasswordMismatch {
		t.Errorf("Login with a wrong password = %v, want ErrPasswordMismatch", err)
	}
	if err := a.Login(c, user, "someone-else@example.com", "").Err; err != ErrUsernameMismatch {
		t.Errorf("Login with a mismatched username = %v, want ErrUsernameMismatch", err)
	}
	if err := a.Login(c, nil, "ada@example.com", "").Err; err != ErrUsernameMismatch {
		t.Errorf("Login with no user = %v, want ErrUsernameMismatch", err)
	}
}

// An empty id is refused on both paths: sub is the identity, and an empty one
// mints a credential whose very next request fails.
func TestLoginAsRefusesAnEmptyID(t *testing.T) {
	a, ctx := newSessionAuth(t)
	a.userLoader, _ = loaderFor()
	c := newCheckContext(ctx, nil)

	if err := a.LoginAs(c, &passwordlessUser{id: "", email: "ada@example.com"}).Err; err != ErrMissingUserID {
		t.Errorf("LoginAs with an empty id = %v, want ErrMissingUserID", err)
	}
}

func TestLoginAsRefusesANilUser(t *testing.T) {
	a, ctx := newSessionAuth(t)
	a.userLoader, _ = loaderFor()
	if err := a.LoginAs(newCheckContext(ctx, nil), nil).Err; err == nil {
		t.Error("LoginAs admitted a nil user")
	}
}
