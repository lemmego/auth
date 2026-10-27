# lemmego/auth

Authentication for Lemmego applications: who is making this request. Sessions,
JWT, and signing in with GitHub or Google.

It answers only *who*. What they are allowed to do is
[`lemmego/authz`](https://github.com/lemmego/authz)'s question.

```go
import "github.com/lemmego/auth"

// A route only a signed-in person reaches
r.Get("/settings", auth.Protected, handlers.Settings)

// Your handler
user, ok := auth.UserAs[*models.User](c)
```

## Install

```bash
go get github.com/lemmego/auth
```

## Register it

```go
// bootstrap/providers.go
&auth.Provider{Opts: &auth.Opts{
    JwtSecret:  config.MustEnv("JWT_SECRET", config.MustEnv("APP_KEY", "")),
    HomeRoute:  "/",
    UserLoader: func(c app.Context, id string) (any, error) {
        return repos.User(c.App()).FindByID(c.RequestContext(), id)
    },
}}
```

List it **after** the session provider, because a session-backed sign-in needs
the session store registered first.

`&auth.Provider{}` with no options is valid and takes the defaults: sessions
on, no JWT. If you end up with neither a session nor a JWT secret, nothing can
authenticate — you get a warning at boot rather than a refusal, so that
`lemmego run appkey` can still boot this provider stack to generate the key
that fixes it. `Check` fails closed meanwhile, so no request is authenticated
in that state.

## `UserLoader` is the one thing you must write

This package never queries anything. A verified credential carries an
identifier and nothing else, so every authenticated request ends at your
loader, and whatever it returns is what `auth.UserAs` hands your handler —
under a session cookie, a JWT cookie and a bearer token alike. That sameness
is the point: one shape, one source of truth.

It takes an `app.Context` rather than a `context.Context` because
`LoadProviders()` takes no arguments and runs before the container is
populated, so a loader declared there has no `app.App` to close over.
`c.App()` is the route from that declaration to your repository.

**The contract matters more than the signature**, because getting it wrong
turns a stale credential into an outage:

| Situation | Return | Result |
|---|---|---|
| Found | the user | your handler runs |
| The id names nobody | an error satisfying `errors.Is(err, auth.ErrUserNotFound)` | **401**, the credential is destroyed, the next request is anonymous |
| An id you cannot even parse | `ErrUserNotFound` — not a failure | same as above |
| The store could not answer | any other error | **503**, the credential survives |

That last row is why the distinction is worth care. Reporting "could not
answer" for an unparsable id makes a fake outage; reporting `ErrUserNotFound`
for a database blip logs everybody out and then stampedes your sign-in page
when they all retry.

A nil user with a nil error, and a typed nil pointer, are both read as
`ErrUserNotFound`. Neither ever authenticates anybody.

## Signing somebody in

```go
result := auth.Login(c, user, username, password)
if result.Err != nil { … }
```

`Login` verifies a bcrypt password and establishes the session and the token.
You fetch the row first, because checking a password means having the hash,
and only you know where your users live.

**`LoginAs` is the same thing without the password check** — session rotation,
token minting, everything after it:

```go
result := auth.LoginAs(c, user)
```

Reach for it whenever the credential is not a password: an OAuth2 callback, a
magic link, an email confirmation, an admin impersonating somebody. You are
responsible for having verified the identity; `LoginAs` will not do it for
you.

This is also what a social account needs. An account created from a GitHub
sign-in has **no password**, and `Login` compares a bcrypt hash — an empty
hash fails against every input, so such an account cannot be signed into by
password even by accident.

## Reading the current user

| Call | Gives you |
|---|---|
| `auth.UserAs[T](c)` | the user as `T`, under any credential |
| `auth.UserID(c)` | the verified identifier, without loading anything |
| `auth.IsAuthenticated(c)` | whether the request carries a verified identity |
| `auth.AuthUser(c)` | the user untyped |

`UserID` stays available when the user itself could not be loaded, which is
what lets a 401 still say which credential it refused.

## Middleware

| Middleware | Behaviour |
|---|---|
| `auth.Protected` | **401** unless the request carries a verified identity |
| `auth.Guest` | redirects a signed-in person to `HomeRoute` — for `/login`, `/register` |
| `auth.OptionalAuth` | resolves the user if there is one, never blocks |

`Protected` answers 401 rather than redirecting to a sign-in page, so put
`auth.Guest` on the pages a signed-in person should not see and let your
frontend decide where a 401 goes.

It does not flatten everything into 401, which matters when you are reading
logs:

| Cause | Status |
|---|---|
| no credential, or one naming nobody | 401 |
| the user store could not answer | 503 |
| no `UserLoader`, or no session and no JWT secret | 500 |

A misconfiguration answering 401 would send you hunting for a bad password.

Reach for `OptionalAuth` on any page that renders differently for a visitor
than for a member — and note the ordering trap: middleware that reads the user
must run *after* it, so a shell or layout middleware prepended ahead of the
route's own `OptionalAuth` will see a signed-out request on a signed-in one.

## Social sign-in

Two drivers ship: `auth/social/github` and `auth/social/google`.

```go
import (
    "github.com/lemmego/auth"
    "github.com/lemmego/auth/social/github"
)

gh, err := github.New(
    config.MustEnv("GITHUB_CLIENT_ID", ""),
    config.MustEnv("GITHUB_CLIENT_SECRET", ""),
)

&auth.Provider{Opts: &auth.Opts{
    // … as above …
    SocialProviders: []auth.SocialProvider{gh},
    SocialStore:     func(a app.App) auth.SocialStore { return repos.Social(a) },
    AppURL:          config.MustEnv("APP_URL", "http://localhost:8080"),
}}
```

`SocialStore` is a function rather than a value for the same reason
`UserLoader` takes an `app.Context`: `LoadProviders` runs before the container
exists, so a store that needs your database connection cannot be built where
the options are written. It is called once, during `Provide`.

`AppURL` is required, because a provider compares the redirect URI against
what you registered with it, exactly. Deriving it from the request's `Host`
would mean a proxy that rewrites `Host` silently breaks every sign-in.

### Routes are yours to mount

This package mounts nothing. Register two routes and call two methods:

```go
guest.Get("/auth/{provider}", handlers.SocialStart)
r.Get("/auth/{provider}/callback", auth.OptionalAuth, handlers.SocialCallback)
```

```go
// handlers.SocialStart
provider := c.Param("provider")
where, err := auth.Get(c.App()).StartSocial(c, provider)
if err != nil { … }          // ErrNoSocialProvider is a 404, not a 500
return c.Redirect(where)

// handlers.SocialCallback
result := auth.Get(c.App()).CompleteSocial(c, c.Param("provider"),
    c.Query("code"), c.Query("state"))
if result.Err != nil { … }
return c.Redirect("/")
```

`StartSocial` generates the `state` and stores it in the session, which is the
only place it can be bound to the browser that started the flow. A driver
refuses an empty `state` rather than inventing one — a value the driver made
up is bound to nothing, which is a CSRF hole wearing the name of its own
defence.

Put `OptionalAuth` on the callback and not `Guest`: somebody already signed in
may be linking an identity, and `Guest` would bounce them with nothing
attached.

### Linking policy

When a provider returns an email that already has an account, `Opts.LinkPolicy`
decides what happens.

| Policy | Behaviour |
|---|---|
| **`LinkVerifiedOnly`** (default) | Links only when the provider says the address is verified **and** the existing account's own address is confirmed. Anything else is `ErrLinkRefused`, and the person is told to sign in and link it from their settings. |
| `LinkNever` | No automatic linking at all. An identity is attached from settings, by somebody already signed in. |
| `LinkAlways` | Links on a matching address, verified or not. **Do not use this.** |

The default's two conditions close different holes. An unverified provider
address lets anybody claim somebody else's account by putting their email on a
throwaway; an unconfirmed local address means your application never proved
the account's owner reads that inbox either.

`LinkNever` is stricter, and costs a returning person who forgot they had a
password a trip through the reset flow.

`LinkAlways` trusts a third party's unverified claim with full access to an
account, which is a takeover anybody can perform at a provider that does not
verify addresses. It is reachable only by writing its name down, which is the
point: a policy nobody can name is a policy nobody can review.

If you offer linking from a settings page, `LinkSocial` is the method for it.
It signs nobody in and returns no credential — proving control of a GitHub
account is not a session, and a method that also logged somebody in would be a
second way into an account.

### What you implement

`SocialStore` is four transitions rather than a repository, because each one is
a decision the policy depends on:

```go
FindBySocialIdentity(ctx, provider, subject) (UserProvider, error)
FindByEmail(ctx, email) (user UserProvider, emailConfirmed bool, err error)
LinkSocialIdentity(ctx, userID string, identity SocialIdentity) error
CreateFromSocialIdentity(ctx, identity SocialIdentity) (UserProvider, error)
```

Three things to get right:

- **Key on `Subject`, never on the email.** An address can change hands, and
  at least one provider lets somebody change theirs. A linked account that
  followed the email would follow it to whoever owns it next.
- **`LinkSocialIdentity` must be idempotent, and must refuse to move an
  identity already attached to somebody else.** That would be one person
  taking over another's sign-in.
- **`FindByEmail` reports whether that account's address is confirmed**,
  because `LinkVerifiedOnly` needs both halves and only you know the second.

The access token is not returned to you. This flow signs somebody in and wants
nothing else from the provider, so holding a token would mean holding a
credential to somebody else's service for no reason — and a credential nobody
needs is one that can only leak.

## Writing your own driver

Two methods, because the flow is two steps:

```go
type SocialProvider interface {
    Name() string
    AuthorizeURL(state, redirectURI string) (string, error)
    Identity(ctx context.Context, code, redirectURI string) (*SocialIdentity, error)
}
```

`Name()` is what appears in the URL: `/auth/{name}`. Refuse an empty `state`.
Fill `EmailVerified` from what the provider actually claims, because the whole
linking policy turns on it — and treat `Handle` as a suggestion rather than a
reservation, since GitHub has one and Google does not.

Both shipped drivers are hand-rolled over `net/http`: the dance is one
redirect and one POST, and an OAuth library's value is in the token refresh
this never needs.

## Testing

```bash
go test ./...
GOWORK=off go test ./...   # as a published module
```

With `lemmego/apptest`, `ActingAs(user.GetID())` signs a request in without
going through a credential at all.
