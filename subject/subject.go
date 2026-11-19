// Package subject qualifies a credential's identifier with the population it
// belongs to.
//
// # Why a bare id is not enough
//
// An application with more than one population of people who can sign in —
// customers in one table, administrators in another, platform staff in a
// third — has independent primary keys in each. User 42, administrator 42
// and staff member 42 are three unrelated people.
//
// A credential carries an identifier and nothing else. A session cookie is
// host-only, so a cookie minted on one host cannot reach another and the
// host alone would disambiguate it. A bearer token is not: one signing key
// signs every surface's tokens and an Authorization header goes wherever the
// client sends it. So an administrator's token for id 42, presented to a
// customer-facing host, is looked up in the customers table and
// authenticates customer 42 — a different person, with a different password,
// in somebody else's account.
//
// The fix is to put the population in the identifier. "admin:42" cannot be
// read as a customer, so the credential is useless on the wrong surface
// whatever the client does with it — and the loader refuses it rather than
// resolving it to the wrong row.
//
// Deliberately NOT inferred from the host. "Trust the Host header" is one
// deployment mistake — a proxy that rewrites it, a cookie scoped to the
// parent domain — away from being wrong, and the failure is silent
// authentication as somebody else.
//
// # The populations are the application's; the mechanism is here
//
// This package ships no list of kinds. What a population is called is a
// product decision, it appears in that application's credentials and
// database, and a framework that enumerated three of them would be wrong for
// every application with a fourth. So an application declares its own Kinds
// and this package holds the qualifying, the parsing and the refusing.
//
// Standard library only, so the vocabulary costs a consumer nothing.
package subject

import (
	"errors"
	"fmt"
	"slices"
	"strings"
)

// Separator divides a subject's kind from its key.
//
// A colon, and neither half may contain one — which is checked rather than
// assumed, because a key holding the separator would make one subject parse
// as another.
const Separator = ":"

var (
	// ErrMalformed means the string is not a subject at all.
	ErrMalformed = errors.New("subject: malformed subject")

	// ErrUnknownKind means the population is not one this application has.
	ErrUnknownKind = errors.New("subject: unknown population")
)

// Kind is one population of people who can sign in.
//
// A string rather than an integer, because this value is serialised into
// every credential an application issues: an integer would make the wire
// format depend on declaration order, and reordering a const block would
// silently repopulate every live session.
type Kind string

// Subject is a credential's identifier: which population, and who within it.
type Subject struct {
	Kind Kind

	// Key identifies the person within their population — typically a
	// decimal id or a uuid.
	Key string
}

// Of builds a subject.
func Of(kind Kind, key string) Subject { return Subject{Kind: kind, Key: key} }

// IsZero reports whether this is the empty subject.
func (s Subject) IsZero() bool { return s.Kind == "" && s.Key == "" }

// String is the wire form: "user:42", "admin:0f8c…".
//
// The zero subject stringifies to "", which is what auth treats as "no
// identifier" — so a login that forgot to set the subject fails at the login
// rather than minting a credential whose next request cannot be resolved.
func (s Subject) String() string {
	if s.Kind == "" || s.Key == "" {
		return ""
	}
	return string(s.Kind) + Separator + s.Key
}

// MustMatch reports whether a subject belongs to the expected population.
//
// A named method rather than a comparison at each call site, because the
// error it returns is the one worth reading: it says which credential
// arrived where, which is the difference between diagnosing a misconfigured
// proxy in a minute and hunting a phantom permission bug for a day.
func (s Subject) MustMatch(want Kind) error {
	if s.Kind != want {
		return fmt.Errorf("%w: this credential identifies a %q and %q was expected",
			ErrUnknownKind, s.Kind, want)
	}
	return nil
}

// Kinds is the populations one application has.
//
// A value rather than a package-level list, for the reason modules.Registry
// is a value: a global works until a test wants two of them, and then one
// test's registrations satisfy another's assertions.
type Kinds struct {
	known []Kind
}

// NewKinds declares an application's populations.
//
// Order is preserved, so All and any screen built from it are stable.
// Duplicates and blank kinds are an error rather than a silent collapse: a
// typo that registered two populations under one name would send one
// population's credentials to the other's loader, which is the exact
// confusion this package exists to prevent.
func NewKinds(kinds ...Kind) (*Kinds, error) {
	k := &Kinds{}
	for _, kind := range kinds {
		if err := validKind(kind); err != nil {
			return nil, err
		}
		if slices.Contains(k.known, kind) {
			return nil, fmt.Errorf("%w: %q is declared twice", ErrMalformed, kind)
		}
		k.known = append(k.known, kind)
	}
	return k, nil
}

// MustKinds is NewKinds for a declaration at package scope, where there is
// nothing to return an error to. It panics, which is right at boot and wrong
// anywhere else.
func MustKinds(kinds ...Kind) *Kinds {
	k, err := NewKinds(kinds...)
	if err != nil {
		panic(err)
	}
	return k
}

func validKind(kind Kind) error {
	if kind == "" {
		return fmt.Errorf("%w: a population needs a name", ErrMalformed)
	}
	if strings.Contains(string(kind), Separator) {
		return fmt.Errorf("%w: the population %q contains %q, which divides a "+
			"subject — so one subject would parse as another",
			ErrMalformed, kind, Separator)
	}
	if strings.TrimSpace(string(kind)) != string(kind) {
		return fmt.Errorf("%w: the population %q has surrounding space", ErrMalformed, kind)
	}
	return nil
}

// Has reports whether a kind is one of this application's.
func (k *Kinds) Has(kind Kind) bool { return slices.Contains(k.known, kind) }

// All lists every population, in declaration order, so a caller can iterate
// rather than enumerate a list that will one day be out of date.
func (k *Kinds) All() []Kind { return slices.Clone(k.known) }

// Parse reads the wire form.
//
// A string with no separator is REFUSED rather than read as the first
// population, and that is the whole reason this function exists with its own
// tests. Defaulting an unqualified id to the commonest population is how a
// credential minted for one gets silently accepted as another — which is the
// confusion the qualifier was introduced to prevent. It would also make
// every old credential keep working across a change whose entire point is
// that they must not.
func (k *Kinds) Parse(raw string) (Subject, error) {
	kindPart, keyPart, found := strings.Cut(raw, Separator)
	if !found {
		return Subject{}, fmt.Errorf("%w: %q names no population", ErrMalformed, raw)
	}
	kind := Kind(kindPart)
	if !k.Has(kind) {
		return Subject{}, fmt.Errorf("%w: %q", ErrUnknownKind, kindPart)
	}
	if !ValidKey(keyPart) {
		return Subject{}, fmt.Errorf("%w: %q is not an identifier", ErrMalformed, keyPart)
	}
	return Subject{Kind: kind, Key: keyPart}, nil
}

// ValidKey reports whether a key is usable.
//
// Strict on purpose. This value is concatenated into a credential, a cache
// key and a signed token's payload, so a key containing the separator, a
// space or a newline would make one subject parse as another. Letters,
// digits and inner hyphens admit a decimal id and a uuid, which is what
// identity tables actually produce.
//
// Validated and never transformed: a key quietly re-encoded to fit would no
// longer match the row it came from, so the right answer to an unusable one
// is to refuse it at the login rather than to repair it.
func ValidKey(key string) bool {
	if key == "" || len(key) > MaxKeyLen {
		return false
	}
	for i := 0; i < len(key); i++ {
		c := key[i]
		switch {
		case c >= '0' && c <= '9', c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z':
		case c == '-' && i > 0 && i < len(key)-1:
		default:
			return false
		}
	}
	return true
}

// MaxKeyLen bounds a key, because it arrives from a credential and is used
// as a map key and a cache key.
const MaxKeyLen = 64
