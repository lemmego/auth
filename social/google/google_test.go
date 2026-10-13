package google

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

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
	provider.tokenURL = server.URL + "/token"
	provider.userinfoURL = server.URL + "/userinfo"
	return provider
}

func TestAuthorizeURLRefusesAnEmptyState(t *testing.T) {
	provider, _ := New("id", "secret")

	if _, err := provider.AuthorizeURL("", "https://app.test/cb"); err == nil {
		t.Fatal("an empty state was accepted")
	}
	if _, err := provider.AuthorizeURL("state", ""); err == nil {
		t.Fatal("an empty redirect URI was accepted")
	}
}

func TestAuthorizeURLAsksForOpenIDAndSelectsAnAccount(t *testing.T) {
	provider, _ := New("id", "secret")

	where, err := provider.AuthorizeURL("state", "https://app.test/cb")
	if err != nil {
		t.Fatalf("AuthorizeURL: %v", err)
	}
	// openid is what makes this OpenID Connect rather than bare OAuth, and
	// email is what carries the verified flag.
	if !strings.Contains(where, "openid") || !strings.Contains(where, "email") {
		t.Fatalf("the scopes are wrong: %s", where)
	}
	// So somebody on a shared machine is shown which account they are about
	// to use rather than being signed in as whoever Google remembers.
	if !strings.Contains(where, "prompt=select_account") {
		t.Fatalf("the URL does not ask Google to show the account picker: %s", where)
	}
	// No refresh token is requested, because nothing here uses one and it
	// would be a long-lived credential held for no purpose.
	if !strings.Contains(where, "access_type=online") {
		t.Fatalf("the URL asks for offline access: %s", where)
	}
}

func TestAVerifiedIdentityIsCarriedThrough(t *testing.T) {
	provider := serve(t, map[string]func(http.ResponseWriter, *http.Request){
		"/token": func(w http.ResponseWriter, _ *http.Request) {
			json.NewEncoder(w).Encode(map[string]string{
				"access_token": "ya29.token", "id_token": "ignored",
			})
		},
		"/userinfo": func(w http.ResponseWriter, _ *http.Request) {
			json.NewEncoder(w).Encode(map[string]any{
				"sub": "11223344", "email": "Ada@Example.com",
				"email_verified": true, "name": "Ada Lovelace",
				"picture": "https://pictures/1",
			})
		},
	})

	identity, err := provider.Identity(context.Background(), "code", "https://app.test/cb")
	if err != nil {
		t.Fatalf("Identity: %v", err)
	}

	// The OpenID subject, not the email: a Workspace address can be
	// reassigned when somebody leaves, and a link that followed the email
	// would follow it to whoever gets it next.
	if identity.Subject != "11223344" {
		t.Fatalf("got subject %q", identity.Subject)
	}
	if identity.Email != "ada@example.com" {
		t.Fatalf("got email %q, want it lowercased", identity.Email)
	}
	if !identity.EmailVerified {
		t.Fatal("email_verified was not carried through")
	}
	// Google has no handle, so none is suggested rather than one invented.
	if identity.Handle != "" {
		t.Fatalf("got handle %q, want none", identity.Handle)
	}
}

// The field the entire linking policy turns on has to survive being false.
func TestAnUnverifiedEmailStaysUnverified(t *testing.T) {
	provider := serve(t, map[string]func(http.ResponseWriter, *http.Request){
		"/token": func(w http.ResponseWriter, _ *http.Request) {
			json.NewEncoder(w).Encode(map[string]string{"access_token": "t"})
		},
		"/userinfo": func(w http.ResponseWriter, _ *http.Request) {
			json.NewEncoder(w).Encode(map[string]any{
				"sub": "1", "email": "ada@example.com", "email_verified": false,
			})
		},
	})

	identity, err := provider.Identity(context.Background(), "code", "https://app.test/cb")
	if err != nil {
		t.Fatalf("Identity: %v", err)
	}
	if identity.EmailVerified {
		t.Fatal("an unverified address was reported as verified")
	}
}

func TestARefusedExchangeIsReported(t *testing.T) {
	provider := serve(t, map[string]func(http.ResponseWriter, *http.Request){
		"/token": func(w http.ResponseWriter, _ *http.Request) {
			json.NewEncoder(w).Encode(map[string]string{
				"error": "invalid_grant", "error_description": "code expired",
			})
		},
	})

	_, err := provider.Identity(context.Background(), "code", "https://app.test/cb")
	if err == nil {
		t.Fatal("a refused exchange was accepted")
	}
	if !strings.Contains(err.Error(), "invalid_grant") {
		t.Fatalf("the refusal lost its cause: %v", err)
	}
}

func TestAProfileWithNoSubjectIsRefused(t *testing.T) {
	provider := serve(t, map[string]func(http.ResponseWriter, *http.Request){
		"/token": func(w http.ResponseWriter, _ *http.Request) {
			json.NewEncoder(w).Encode(map[string]string{"access_token": "t"})
		},
		"/userinfo": func(w http.ResponseWriter, _ *http.Request) {
			json.NewEncoder(w).Encode(map[string]any{"email": "ada@example.com"})
		},
	})

	_, err := provider.Identity(context.Background(), "code", "https://app.test/cb")
	if err == nil {
		t.Fatal("a profile with no subject was accepted")
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
