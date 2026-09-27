package auth

import "github.com/lemmego/api/app"

const (
	// UserKey is where the loaded user is put on the request context.
	//
	// It is a request key only, never a session key: the session holds an
	// identifier now, and conflating the two is why consumers ended up
	// probing both c.Get and c.Session for the same thing.
	UserKey = "auth:user"

	// UserIDKey is the verified identifier, on the request context and in the
	// session.
	//
	// It is set as soon as a credential verifies, before the user is loaded,
	// so anything that only needs an id — a consent screen, an audit line —
	// works even when the load fails.
	UserIDKey = "auth:user_id"

	// authenticatedKey marks a request that authenticated with no user behind
	// it, which is what a client-credentials token is: a caller with an
	// identity that is not a person.
	authenticatedKey = "auth:authenticated"

	// loadErrorKey memoises a failed load for the rest of the request.
	loadErrorKey = "auth:load_error"
)

// UserAs returns the authenticated user as T.
//
//	user, ok := auth.UserAs[*models.User](c)
//	if ok {
//	    fmt.Println(user.Email)
//	}
//
// The same T succeeds under a session, a JWT cookie and a bearer token,
// because all three end at the same loader. That is the guarantee this package
// makes, and its one precondition is that a UserLoader is configured.
//
// It is a free function rather than a method on Auth: reaching Auth means
// app.Get, which panics in an application that runs the oauth2 bearer guard
// without registering this package's provider — and that application still has
// a perfectly good user on its context. The name matches the framework's
// existing vocabulary for the same move, session.GetAs and cache.GetAs.
func UserAs[T any](c app.Context) (T, bool) {
	user, ok := c.Get(UserKey).(T)
	return user, ok
}

// AuthUser returns the authenticated user untyped, for code that genuinely
// cannot name the type. Prefer UserAs.
func AuthUser(c app.Context) any { return c.Get(UserKey) }

// UserID returns the verified identifier of the authenticated user.
//
// It is available without loading anything, and remains available when the
// load failed — so a handler that only needs an id never pays for a row it
// does not read.
func UserID(c app.Context) (string, bool) {
	id, ok := c.Get(UserIDKey).(string)
	return id, ok && id != ""
}

// SetSubject records a verified identifier established elsewhere, so this
// package's loader turns it into the application's user.
//
// This is the seam an external verifier uses — the oauth2 bearer guard, a
// signed-header gateway, a test harness. It hands over an id rather than a
// user, which is a narrower coupling than passing an object and is what lets
// every path produce the same type.
func SetSubject(c app.Context, id string) { c.Set(UserIDKey, id) }

// SetAuthenticated marks a request as authenticated with no user behind it.
//
// A client-credentials token is the case: the caller is a machine acting as
// itself, so Protected must admit it while AuthUser stays nil. Inventing a
// user for it would be a lie, and it was the old behaviour.
func SetAuthenticated(c app.Context) { c.Set(authenticatedKey, true) }

// IsAuthenticated reports whether the request carries any verified identity,
// with or without a user behind it.
func IsAuthenticated(c app.Context) bool {
	if c.Get(UserKey) != nil {
		return true
	}
	marked, _ := c.Get(authenticatedKey).(bool)
	return marked
}
