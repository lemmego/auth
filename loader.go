package auth

import (
	"errors"
	"net/http"
	"reflect"

	"github.com/lemmego/api/app"
)

// UserLoader turns the identifier a verified credential carries into the
// application's own user.
//
// This package never queries anything: UserProvider is three getters with no
// lookup, and auth has no idea what a user is or where it lives. So every
// authenticated request ends here, and whatever this returns is what UserAs
// hands to the handler — under a session cookie, a JWT cookie and a bearer
// token alike. That sameness is the point. The credential carries an id and
// nothing else, so there is one shape and one source of truth.
//
// It takes an app.Context rather than a context.Context for a practical
// reason: LoadProviders() takes no arguments and runs before the container is
// populated, so a loader declared there has no app.App to close over. c.App()
// is the only route from that declaration to the repository.
//
// The contract:
//
//   - Return the user on success.
//   - Return an error satisfying errors.Is(err, ErrUserNotFound) when the id
//     names nobody. That is a 401, and the credential is destroyed so the next
//     request is simply anonymous.
//   - An id you cannot even parse — a credential issued before the format
//     changed, or a fabricated one — is ErrUserNotFound, NOT an error.
//     Reporting a stale credential as a failure turns it into a fake outage,
//     which is the one inversion this design exists to prevent.
//   - Return any other error only when the store could not answer. That is a
//     503 and the credential survives, so a database blip does not log
//     everyone out and then stampede the login page when they all retry.
//
// A nil user with a nil error, and a typed nil pointer, are both read as
// ErrUserNotFound. Neither may ever authenticate anyone.
type UserLoader func(c app.Context, id string) (any, error)

var (
	// ErrUserNotFound reports that a verified credential names a user who no
	// longer exists. It is the only loader outcome that logs someone out.
	ErrUserNotFound = errors.New("auth: user not found")

	// ErrNoUserLoader reports that a credential verified but no UserLoader is
	// configured, so there is nobody to fetch. Nothing authenticates in this
	// state — the same fail-closed posture as ErrNoAuthMechanism.
	ErrNoUserLoader = errors.New("auth: no user loader is configured")
)

// UserStoreUnavailableError wraps a loader failure that is not the user's
// fault, so it renders as 503 rather than 401.
//
// The distinction is the whole reason the loader has two failure modes. A
// deleted account and an unreachable database are different events: one should
// log that person out, the other should tell everyone to come back shortly and
// leave their credentials intact.
//
// It carries an app.HttpMessage, which the framework's error handling picks up
// through its generic errors.As fallback, so no new sentinel is needed there.
type UserStoreUnavailableError struct {
	app.HttpMessage
	Err error
}

func (e *UserStoreUnavailableError) Error() string {
	return "auth: the user store could not answer: " + e.Err.Error()
}

func (e *UserStoreUnavailableError) GetHttpMessage() app.HttpMessage { return e.HttpMessage }

func (e *UserStoreUnavailableError) Unwrap() error { return e.Err }

func unavailable(err error) *UserStoreUnavailableError {
	return &UserStoreUnavailableError{
		HttpMessage: app.HttpMessage{
			Status:  http.StatusServiceUnavailable,
			Message: "the service is temporarily unavailable",
		},
		Err: err,
	}
}

// LoaderFrom returns the application's configured loader, or nil.
//
// It does not panic when auth is unregistered: an application may run the
// oauth2 bearer guard without this package's session and JWT handling, and
// app.Get panics on a missing service.
func LoaderFrom(c app.Context) UserLoader {
	a, ok := app.Lookup[*Auth](c.App())
	if !ok || a == nil {
		return nil
	}
	return a.userLoader
}

// isNilUser reports whether a loader returned nothing usable.
//
// A typed nil — (*models.User)(nil) — is not nil as an any, so without this it
// would satisfy both the "already resolved" short-circuit and UserAs's type
// assertion. The handler would believe it was authenticated and dereference a
// nil pointer on the first field it read.
func isNilUser(user any) bool {
	if user == nil {
		return true
	}
	switch value := reflect.ValueOf(user); value.Kind() {
	case reflect.Ptr, reflect.Interface, reflect.Map, reflect.Slice, reflect.Func:
		return value.IsNil()
	}
	return false
}
