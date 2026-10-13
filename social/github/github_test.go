package github

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// serve stands in for GitHub. The driver's endpoint fields are unexported and
// only reachable from this package, so a production build has no way to point
// it at somebody else's authorization server.
func serve(t *testing.T, routes map[string]func(http.ResponseWriter, *http.Request)) *Provider {
	t.Helper()

	mux := http.NewServeMux()
	for path, handler := range routes {
		mux.HandleFunc(path, handler)
	}
	server := httptest.NewServer(mux)
	t.Cleanup(server.Close)

	provider, err := New("client-id", "client-secret")
	if err != nil {
		t.Fatalf("building the driver: %v", err)
	}
	provider.tokenURL = server.URL + "/login/oauth/access_token"
	provider.apiURL = server.URL
	return provider
}

func token(scope string) func(http.ResponseWriter, *http.Request) {
	return func(w http.ResponseWriter, _ *http.Request) {
		json.NewEncoder(w).Encode(map[string]string{
			"access_token": "gho_token", "scope": scope, "token_type": "bearer",
		})
	}
}

// A state the driver invented would be bound to nothing, which is a CSRF hole
// wearing the name of its own defence. pay/stripe refuses the same way.
func TestAuthorizeURLRefusesAnEmptyState(t *testing.T) {
	provider, err := New("id", "secret")
	if err != nil {
		t.Fatalf("building the driver: %v", err)
	}

	if _, err := provider.AuthorizeURL("", "https://app.test/auth/github/callback"); err == nil {
		t.Fatal("an empty state was accepted")
	}
	if _, err := provider.AuthorizeURL("state", ""); err == nil {
		t.Fatal("an empty redirect URI was accepted")
	}
}

func TestAuthorizeURLAsksForTheEmailScope(t *testing.T) {
	provider, _ := New("id", "secret")

	where, err := provider.AuthorizeURL("state", "https://app.test/cb")
	if err != nil {
		t.Fatalf("AuthorizeURL: %v", err)
	}
	// Without user:email the verified address is unreachable, so every
	// sign-in would arrive unverified and no account could ever be linked —
	// for a reason nobody could diagnose from the outside.
	if !strings.Contains(where, "user%3Aemail") {
		t.Fatalf("the authorize URL does not request user:email: %s", where)
	}
	if !strings.Contains(where, "state=state") {
		t.Fatalf("the state is not in the URL: %s", where)
	}
}

// The detail the whole linking policy rests on: GET /user returns the public
// profile email, which GitHub never marks verified. The verified primary only
// comes from GET /user/emails.
func TestTheVerifiedEmailComesFromTheEmailsEndpoint(t *testing.T) {
	provider := serve(t, map[string]func(http.ResponseWriter, *http.Request){
		"/login/oauth/access_token": token("read:user,user:email"),
		"/user": func(w http.ResponseWriter, _ *http.Request) {
			json.NewEncoder(w).Encode(map[string]any{
				"id": 42, "login": "Ada", "name": "Ada Lovelace",
				// The public profile address, and a different one.
				"email": "public@example.com", "avatar_url": "https://avatars/1",
			})
		},
		"/user/emails": func(w http.ResponseWriter, _ *http.Request) {
			json.NewEncoder(w).Encode([]map[string]any{
				{"email": "secondary@example.com", "primary": false, "verified": true},
				{"email": "Ada@Example.com", "primary": true, "verified": true},
			})
		},
	})

	identity, err := provider.Identity(context.Background(), "code", "https://app.test/cb")
	if err != nil {
		t.Fatalf("Identity: %v", err)
	}

	if identity.Email != "ada@example.com" {
		t.Fatalf("got email %q, want the lowercased verified primary", identity.Email)
	}
	if !identity.EmailVerified {
		t.Fatal("the verified primary was not reported as verified")
	}
	if identity.Subject != "42" {
		t.Fatalf("got subject %q, want 42 — the provider's own id is what "+
			"identities are keyed on", identity.Subject)
	}
	if identity.Handle != "ada" {
		t.Fatalf("got handle %q, want the lowercased login", identity.Handle)
	}
}

// Falling back to the public profile email is allowed, but it must never be
// marked verified — treating it as verified is exactly the account takeover
// the policy exists to prevent.
func TestThePublicProfileEmailIsNeverVerified(t *testing.T) {
	provider := serve(t, map[string]func(http.ResponseWriter, *http.Request){
		"/login/oauth/access_token": token("read:user,user:email"),
		"/user": func(w http.ResponseWriter, _ *http.Request) {
			json.NewEncoder(w).Encode(map[string]any{
				"id": 42, "login": "ada", "email": "public@example.com",
			})
		},
		// The emails endpoint fails, so the fallback is taken.
		"/user/emails": func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusForbidden)
		},
	})

	identity, err := provider.Identity(context.Background(), "code", "https://app.test/cb")
	if err != nil {
		t.Fatalf("Identity: %v", err)
	}
	if identity.Email != "public@example.com" {
		t.Fatalf("got email %q", identity.Email)
	}
	if identity.EmailVerified {
		t.Fatal("the public profile email was reported as verified, which " +
			"would let anybody claim an account by putting its address on a " +
			"throwaway GitHub profile")
	}
}

// Only the primary. Taking the first verified address instead would let
// somebody add an address they do not use as primary and sign in as whoever
// owns it here.
func TestANonPrimaryVerifiedAddressIsNotUsed(t *testing.T) {
	provider := serve(t, map[string]func(http.ResponseWriter, *http.Request){
		"/login/oauth/access_token": token("read:user,user:email"),
		"/user": func(w http.ResponseWriter, _ *http.Request) {
			json.NewEncoder(w).Encode(map[string]any{"id": 42, "login": "ada"})
		},
		"/user/emails": func(w http.ResponseWriter, _ *http.Request) {
			json.NewEncoder(w).Encode([]map[string]any{
				{"email": "someone-elses@example.com", "primary": false, "verified": true},
			})
		},
	})

	identity, err := provider.Identity(context.Background(), "code", "https://app.test/cb")
	if err != nil {
		t.Fatalf("Identity: %v", err)
	}
	if identity.Email == "someone-elses@example.com" {
		t.Fatal("a non-primary address was used, so somebody could sign in " +
			"as whoever owns it here by adding it to their GitHub account")
	}
	if identity.EmailVerified {
		t.Fatalf("got a verified email from nowhere: %q", identity.Email)
	}
}

// pay/stripe checks the scope that comes back rather than assuming it, and
// for the same reason: a grant made before these scopes were set comes back
// narrower, and a narrower grant makes the email lookup silently return
// nothing verified.
func TestANarrowScopeIsRefused(t *testing.T) {
	provider := serve(t, map[string]func(http.ResponseWriter, *http.Request){
		"/login/oauth/access_token": token("read:user"),
	})

	_, err := provider.Identity(context.Background(), "code", "https://app.test/cb")
	if err == nil {
		t.Fatal("a grant that cannot read a verified email was accepted")
	}
	if !strings.Contains(err.Error(), "scope") {
		t.Fatalf("the refusal does not name the scope: %v", err)
	}
}

func TestARefusedExchangeIsReported(t *testing.T) {
	provider := serve(t, map[string]func(http.ResponseWriter, *http.Request){
		"/login/oauth/access_token": func(w http.ResponseWriter, _ *http.Request) {
			json.NewEncoder(w).Encode(map[string]string{
				"error": "bad_verification_code", "error_description": "expired",
			})
		},
	})

	_, err := provider.Identity(context.Background(), "code", "https://app.test/cb")
	if err == nil {
		t.Fatal("a refused exchange was accepted")
	}
	if !strings.Contains(err.Error(), "bad_verification_code") {
		t.Fatalf("the refusal lost its cause: %v", err)
	}
}

func TestAProfileWithNoIDIsRefused(t *testing.T) {
	provider := serve(t, map[string]func(http.ResponseWriter, *http.Request){
		"/login/oauth/access_token": token("read:user,user:email"),
		"/user": func(w http.ResponseWriter, _ *http.Request) {
			json.NewEncoder(w).Encode(map[string]any{"login": "ada"})
		},
	})

	_, err := provider.Identity(context.Background(), "code", "https://app.test/cb")
	if err == nil {
		t.Fatal("a profile with no id was accepted, so nothing could be keyed on it")
	}
}

func TestAnEmptyCodeIsRefusedWithoutACall(t *testing.T) {
	called := false
	provider := serve(t, map[string]func(http.ResponseWriter, *http.Request){
		"/login/oauth/access_token": func(w http.ResponseWriter, _ *http.Request) {
			called = true
		},
	})

	if _, err := provider.Identity(context.Background(), "", "https://app.test/cb"); err == nil {
		t.Fatal("an empty code was accepted")
	}
	if called {
		t.Fatal("the token endpoint was called with no code")
	}
}

func TestNewRefusesIncompleteCredentials(t *testing.T) {
	if _, err := New("", "secret"); err == nil {
		t.Fatal("a driver with no client id was built")
	}
	if _, err := New("id", ""); err == nil {
		t.Fatal("a driver with no client secret was built")
	}
}
