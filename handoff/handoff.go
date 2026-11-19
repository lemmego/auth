// Package handoff mints and verifies the single-use token that carries a
// signed-in identity from one host to another.
//
// # The problem it solves
//
// A session cookie is host-only, and in a multi-tenant application that is
// deliberate: it is what keeps one tenant's session out of another's. So
// somebody signed in on a console host has no credential at all on a tenant
// host, and clicking "open acme" would land them on a sign-in page — often
// for an account whose password they have deliberately never been asked to
// keep the same.
//
// The hop is therefore an explicit, deliberately feeble credential: a token
// the sending host mints, valid for one audience, for one use, for a
// minute. It is redeemed by calling auth.LoginAs, which exists for exactly
// this.
//
// # What the shape has to defend against
//
// The token travels in a URL, because the hop is a redirect a browser
// follows. A URL reaches the server log, the browser's history, and — if the
// landing page ever loads a third-party asset — a Referer header. There is no
// way to make a URL-borne credential private, so this one is made worthless
// instead:
//
//   - single use, enforced by an insert into a unique index rather than a
//     read-then-write, so two simultaneous redemptions cannot both win;
//   - a minute of life, with the maximum enforced at construction;
//   - bound to ONE audience, so a token for acme presented to globex is
//     refused — the token names its audience and the verifier is handed the
//     audience the request actually arrived at;
//   - bound to ONE population, because it carries a subject.Subject: a
//     handoff for an administrator cannot be redeemed as a customer.
//
// And the landing handler should redirect immediately, so the address bar
// holding the token is replaced before anybody can copy it.
//
// Standard library plus auth/subject, which is itself standard library only.
package handoff

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/lemmego/auth/subject"
)

// DefaultVersion prefixes every token and is covered by the signature.
//
// Signed rather than merely present, so a future v2 with different semantics
// cannot be stripped back to v1 by an attacker who prefers the older rules.
//
// Configurable with WithVersion so that two applications sharing a signing
// key — or one application's two unrelated handoffs — cannot redeem each
// other's tokens. Changing it invalidates every token in flight, which for a
// credential that lives a minute is not a migration.
const DefaultVersion = "lmgh1"

const (
	// DefaultTTL is how long a handoff token lives.
	//
	// A minute. The token is redeemed by the redirect that follows its
	// creation, so the only thing a longer life buys is a longer window in
	// which a copy out of a log or a history entry still works.
	DefaultTTL = time.Minute

	// MaxTTL is the longest life this package will sign.
	//
	// Enforced at construction rather than documented, because a
	// URL-borne, log-visible credential with an hour of life is a different
	// and much worse thing than this one, and nobody should be able to
	// configure their way into it by accident.
	MaxTTL = 5 * time.Minute

	// MinSecretLen is the shortest signing key accepted.
	MinSecretLen = 32
)

var (
	// ErrMalformed means the token is not a handoff token.
	ErrMalformed = errors.New("handoff: malformed token")

	// ErrSignature means the token was not signed by this application.
	ErrSignature = errors.New("handoff: bad signature")

	// ErrExpired means the token is past its expiry.
	ErrExpired = errors.New("handoff: expired token")

	// ErrWrongAudience means the token is for a different audience than the
	// one the request arrived at.
	ErrWrongAudience = errors.New("handoff: token is for another audience")

	// ErrUsed means the token has already been redeemed.
	ErrUsed = errors.New("handoff: token has already been used")

	// ErrWeakSecret means the signing key is too short, or absent.
	ErrWeakSecret = errors.New("handoff: signing secret is too short")
)

// Grant is what a token says, once it is known to be genuine.
type Grant struct {
	// ID is the token's unique identifier, and the value the store records
	// to make it single-use. Safe to log: it identifies the token, not the
	// bearer, and it is worthless once redeemed.
	ID string

	// Subject is who is being handed over.
	Subject subject.Subject

	// Audience is the one audience this token is valid for — typically the
	// tenant, or the host, the sending side means it to be redeemed at.
	Audience string

	ExpiresAt time.Time
}

// Store records which tokens have been redeemed.
type Store interface {
	// Consume records a redemption and reports whether this caller is the
	// first.
	//
	// It must be ATOMIC: one statement whose uniqueness the database
	// enforces, not a read followed by a write. Two clicks on one link —
	// or one click and a prefetching browser — arrive at the same instant
	// often enough to matter, and a read-then-write lets both through.
	//
	// expiresAt is passed so the store can prune. A store that kept every
	// id forever would be a table that only grows, which is how a
	// single-use guarantee becomes an operational problem instead.
	Consume(ctx context.Context, id string, expiresAt time.Time) (first bool, err error)
}

// Signer mints and verifies tokens.
type Signer struct {
	key     []byte
	ttl     time.Duration
	now     func() time.Time
	version string
	kinds   *subject.Kinds
}

// Option configures a Signer.
type Option func(*Signer)

// WithTTL sets how long a minted token lives, up to MaxTTL.
func WithTTL(ttl time.Duration) Option { return func(s *Signer) { s.ttl = ttl } }

// WithClock replaces time.Now, for tests.
func WithClock(now func() time.Time) Option { return func(s *Signer) { s.now = now } }

// WithVersion replaces the token prefix, so two applications sharing a
// signing key cannot redeem each other's tokens.
func WithVersion(version string) Option { return func(s *Signer) { s.version = version } }

// NewSigner returns a signer over a secret.
//
// The secret must be at least MinSecretLen bytes. A short one is refused
// rather than accepted with a warning: this is the only thing standing
// between a URL parameter and a session as somebody else, and an application
// that boots with a two-character signing key is an application whose handoff
// is forgeable by anybody who notices.
func NewSigner(secret string, kinds *subject.Kinds, options ...Option) (*Signer, error) {
	if len(secret) < MinSecretLen {
		return nil, fmt.Errorf("%w: %d bytes, want at least %d",
			ErrWeakSecret, len(secret), MinSecretLen)
	}
	if kinds == nil {
		// Not defaulted to "accept any population". A verifier that accepted
		// an unrecognised kind would hand the application a subject it
		// cannot load, and the attacker chooses the kind — which is the one
		// thing the qualifier exists to stop.
		return nil, errors.New("handoff: no populations, so a token's subject " +
			"could not be checked against the ones this application has")
	}
	signer := &Signer{
		key:     []byte(secret),
		ttl:     DefaultTTL,
		now:     time.Now,
		version: DefaultVersion,
		kinds:   kinds,
	}
	for _, option := range options {
		option(signer)
	}
	if !opaque(signer.version) {
		return nil, fmt.Errorf("%w: the version %q must be letters, digits and "+
			"inner hyphens — it is a literal prefix of the token", ErrMalformed, signer.version)
	}
	if signer.ttl <= 0 {
		return nil, fmt.Errorf("handoff: ttl must be positive, got %s", signer.ttl)
	}
	if signer.ttl > MaxTTL {
		return nil, fmt.Errorf(
			"handoff: ttl %s exceeds the maximum of %s; a token that travels in a URL "+
				"and reaches logs, history and referrers must expire quickly",
			signer.ttl, MaxTTL)
	}
	return signer, nil
}

// Mint signs a handoff for one subject into one audience.
func (s *Signer) Mint(sub subject.Subject, audience string) (string, Grant, error) {
	if sub.String() == "" {
		return "", Grant{}, fmt.Errorf("%w: no subject to hand over", ErrMalformed)
	}
	// Checked here as well as at verification, so a population this
	// application does not have cannot be put into a token in the first
	// place — a mistake caught at the mint is a failed redirect, where the
	// same mistake caught at the redemption is a person who cannot sign in
	// and a token already burned.
	if !s.kinds.Has(sub.Kind) {
		return "", Grant{}, fmt.Errorf("%w: %q", subject.ErrUnknownKind, sub.Kind)
	}
	if !subject.ValidKey(sub.Key) {
		return "", Grant{}, fmt.Errorf("%w: %q is not an identifier", ErrMalformed, sub.Key)
	}
	if !opaque(audience) {
		return "", Grant{}, fmt.Errorf("%w: %q is not an audience", ErrMalformed, audience)
	}

	id, err := newID()
	if err != nil {
		return "", Grant{}, err
	}

	grant := Grant{
		ID:        id,
		Subject:   sub,
		Audience:  audience,
		ExpiresAt: s.now().Add(s.ttl).UTC().Truncate(time.Second),
	}

	// The signed message is the literal prefix of the token, so verification
	// authenticates the bytes it received rather than a re-serialisation of
	// what it parsed out of them. Those two differ the moment anything about
	// the encoding is ambiguous, and the difference is a forgery.
	signed := s.version + "." + encode(payload(grant))
	return signed + "." + encode(s.mac(signed)), grant, nil
}

// Verify authenticates a token, confirms it is for this audience, and
// redeems it.
//
// The order of the checks is not arbitrary:
//
//  1. the signature, before anything out of the payload is believed;
//  2. expiry and audience, which are claims the signature now vouches for;
//  3. redemption LAST, so a token is never burned by a request that was
//     going to be refused anyway. Otherwise one mistyped host, or one
//     prefetch from a security scanner, would consume a legitimate link and
//     present the user with "already used".
func (s *Signer) Verify(ctx context.Context, token, audience string, store Store) (Grant, error) {
	if store == nil {
		// Not a silent pass. A nil store means the single-use property is
		// absent, and a replayable handoff token is the one failure mode
		// this package exists to prevent.
		return Grant{}, errors.New("handoff: no store, so the token cannot be made single-use")
	}

	prefix, macPart, found := cut(token)
	if !found {
		return Grant{}, fmt.Errorf("%w: expected three dot-separated parts", ErrMalformed)
	}
	if !strings.HasPrefix(prefix, s.version+".") {
		return Grant{}, fmt.Errorf("%w: not a %s token", ErrMalformed, s.version)
	}

	got, err := decode(macPart)
	if err != nil {
		return Grant{}, fmt.Errorf("%w: unreadable signature", ErrMalformed)
	}
	if !hmac.Equal(got, s.mac(prefix)) {
		return Grant{}, ErrSignature
	}

	raw, err := decode(strings.TrimPrefix(prefix, s.version+"."))
	if err != nil {
		return Grant{}, fmt.Errorf("%w: unreadable payload", ErrMalformed)
	}
	grant, err := s.parsePayload(string(raw))
	if err != nil {
		return Grant{}, err
	}

	if !s.now().UTC().Before(grant.ExpiresAt) {
		return Grant{}, fmt.Errorf("%w: expired at %s", ErrExpired, grant.ExpiresAt.Format(time.RFC3339))
	}

	// Constant time, for consistency rather than because an audience is
	// secret — it is usually in the hostname. What it does buy is that the
	// comparison cannot be the one place in the chain somebody tries to be
	// clever with a prefix match.
	if !hmac.Equal([]byte(grant.Audience), []byte(audience)) {
		return Grant{}, fmt.Errorf("%w: signed for %s, presented to %s",
			ErrWrongAudience, grant.Audience, audience)
	}

	first, err := store.Consume(ctx, grant.ID, grant.ExpiresAt)
	if err != nil {
		return Grant{}, fmt.Errorf("handoff: redeeming %s: %w", grant.ID, err)
	}
	if !first {
		return Grant{}, fmt.Errorf("%w: %s", ErrUsed, grant.ID)
	}
	return grant, nil
}

func (s *Signer) mac(message string) []byte {
	sum := hmac.New(sha256.New, s.key)
	sum.Write([]byte(message))
	return sum.Sum(nil)
}

// payload is the signed claim set.
//
// Four fields separated by a byte none of them may contain — which is
// enforced rather than assumed: a subject's key and an audience are both
// checked when the token is minted, so there is no value either can take
// that would make this parse as a different claim set.
func payload(g Grant) []byte {
	return []byte(strings.Join([]string{
		g.ID,
		g.Audience,
		g.Subject.String(),
		strconv.FormatInt(g.ExpiresAt.Unix(), 10),
	}, "|"))
}

func (s *Signer) parsePayload(raw string) (Grant, error) {
	parts := strings.Split(raw, "|")
	if len(parts) != 4 {
		return Grant{}, fmt.Errorf("%w: %d payload fields, want 4", ErrMalformed, len(parts))
	}
	if !opaque(parts[0]) || !opaque(parts[1]) {
		return Grant{}, fmt.Errorf("%w: unusable token id or audience", ErrMalformed)
	}
	sub, err := s.kinds.Parse(parts[2])
	if err != nil {
		return Grant{}, fmt.Errorf("%w: %w", ErrMalformed, err)
	}
	seconds, err := strconv.ParseInt(parts[3], 10, 64)
	if err != nil {
		return Grant{}, fmt.Errorf("%w: unreadable expiry", ErrMalformed)
	}
	return Grant{
		ID:        parts[0],
		Audience:  parts[1],
		Subject:   sub,
		ExpiresAt: time.Unix(seconds, 0).UTC(),
	}, nil
}

// cut splits "<version>.payload.mac" into its signed prefix and its signature.
func cut(token string) (prefix, mac string, found bool) {
	last := strings.LastIndexByte(token, '.')
	if last <= 0 || last == len(token)-1 {
		return "", "", false
	}
	return token[:last], token[last+1:], true
}

func encode(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

func decode(s string) ([]byte, error) { return base64.RawURLEncoding.DecodeString(s) }

// newID is 128 bits of randomness, hex-encoded.
//
// Not a sequence and not a hash of anything: the id is a primary key in a
// table of redeemed tokens, so a guessable one would let somebody burn a
// link before its owner clicks it.
func newID() (string, error) {
	var raw [16]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return "", fmt.Errorf("handoff: no randomness: %w", err)
	}
	return hex.EncodeToString(raw[:]), nil
}

// opaque is the shape every field in the payload must have: letters, digits
// and inner hyphens, and nothing that could be read as a separator.
//
// The same rule as subject.ValidKey, and deliberately not a call to it: that
// one is about an identity table's keys and this one about a token's fields,
// so they are free to diverge without one change silently widening the
// other.
func opaque(s string) bool {
	if s == "" || len(s) > 64 {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= '0' && c <= '9', c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z':
		case c == '-' && i > 0 && i < len(s)-1:
		default:
			return false
		}
	}
	return true
}
