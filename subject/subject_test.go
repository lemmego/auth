package subject_test

import (
	"errors"
	"slices"
	"strings"
	"testing"

	"github.com/lemmego/auth/subject"
)

// Two populations, declared the way an application declares its own — this
// package ships no list of them, and that is the generalisation.
const (
	kindUser  subject.Kind = "user"
	kindAdmin subject.Kind = "admin"
)

func kinds(t *testing.T) *subject.Kinds {
	t.Helper()
	k, err := subject.NewKinds(kindUser, kindAdmin)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func TestTheWireFormRoundTrips(t *testing.T) {
	k := kinds(t)
	for _, want := range []subject.Subject{
		subject.Of(kindUser, "42"),
		subject.Of(kindAdmin, "0f8c4b2a-1d3e-4f5a-9b7c-2e6d8a0f1b3c"),
		subject.Of(kindUser, "1"),
	} {
		got, err := k.Parse(want.String())
		if err != nil {
			t.Fatalf("%q: %v", want, err)
		}
		if got != want {
			t.Errorf("%q round-tripped to %+v", want, got)
		}
	}
}

// The property the whole package exists for. Defaulting an unqualified id to
// the commonest population is how a credential minted for one gets silently
// accepted as another — and it would make every old credential keep working
// across a change whose entire point is that they must not.
func TestAnUnqualifiedIdentifierIsRefusedAndNotReadAsTheFirstPopulation(t *testing.T) {
	k := kinds(t)
	for _, raw := range []string{"42", "", "0f8c4b2a-1d3e-4f5a-9b7c-2e6d8a0f1b3c", "admin"} {
		got, err := k.Parse(raw)
		if err == nil {
			t.Errorf("%q was accepted as %+v", raw, got)
		}
		if !errors.Is(err, subject.ErrMalformed) && !errors.Is(err, subject.ErrUnknownKind) {
			t.Errorf("%q gave %v, want a malformed or unknown-kind error", raw, err)
		}
	}
}

// A population this application does not have is refused, so a credential
// claiming one cannot be resolved against whatever table happens to be
// first.
func TestAnUndeclaredPopulationIsRefused(t *testing.T) {
	k := kinds(t)
	for _, raw := range []string{"sysadmin:42", "User:42", "ADMIN:42", ":42", "robot:1"} {
		if _, err := k.Parse(raw); !errors.Is(err, subject.ErrUnknownKind) &&
			!errors.Is(err, subject.ErrMalformed) {
			t.Errorf("%q gave %v, want a refusal", raw, err)
		}
	}
	// And one that IS declared still works, so the test is not simply
	// refusing everything.
	if _, err := k.Parse("admin:42"); err != nil {
		t.Fatalf("a declared population was refused: %v", err)
	}
}

// A key is validated and never repaired. This value is concatenated into a
// credential, a cache key and a signed token's payload, so one holding the
// separator would make one subject parse as another.
func TestAnUnusableKeyIsRefused(t *testing.T) {
	k := kinds(t)
	for name, raw := range map[string]string{
		"empty":           "user:",
		"separator":       "user:4:2",
		"space":           "user:4 2",
		"newline":         "user:4\n2",
		"pipe":            "user:a|b",
		"leading hyphen":  "user:-42",
		"trailing hyphen": "user:42-",
		"too long":        "user:" + strings.Repeat("a", 65),
		"slash":           "user:a/b",
		"percent":         "user:a%2f",
	} {
		if got, err := k.Parse(raw); err == nil {
			t.Errorf("%s (%q) was accepted as %+v", name, raw, got)
		}
	}

	// The shapes an identity table actually produces.
	for _, raw := range []string{"user:1", "user:42", "user:" + strings.Repeat("a", 64),
		"admin:0f8c4b2a-1d3e-4f5a-9b7c-2e6d8a0f1b3c"} {
		if _, err := k.Parse(raw); err != nil {
			t.Errorf("%q was refused: %v", raw, err)
		}
	}
}

// The zero subject stringifies to "", which is what auth treats as "no
// identifier" — so a login that forgot to set the subject fails at the login
// rather than minting a credential whose next request cannot be resolved.
func TestTheZeroSubjectHasNoWireForm(t *testing.T) {
	var zero subject.Subject
	if !zero.IsZero() {
		t.Error("the zero subject does not report itself as zero")
	}
	for _, s := range []subject.Subject{
		{},
		{Kind: kindUser},
		{Key: "42"},
	} {
		if s.String() != "" {
			t.Errorf("%+v stringifies to %q, want the empty string", s, s.String())
		}
	}
}

func TestMustMatchNamesBothSides(t *testing.T) {
	s := subject.Of(kindAdmin, "42")
	if err := s.MustMatch(kindAdmin); err != nil {
		t.Fatalf("an administrator failed an administrator requirement: %v", err)
	}
	err := s.MustMatch(kindUser)
	if !errors.Is(err, subject.ErrUnknownKind) {
		t.Fatalf("MustMatch = %v, want ErrUnknownKind", err)
	}
	// The error is the whole reason this is a method rather than a
	// comparison: it is the difference between diagnosing a misconfigured
	// proxy in a minute and hunting a phantom permission bug for a day.
	for _, want := range []string{"admin", "user"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("the error does not name %q: %v", want, err)
		}
	}
}

func TestKindsRefusesADeclarationItCannotHonour(t *testing.T) {
	for name, declared := range map[string][]subject.Kind{
		"blank":           {""},
		"duplicate":       {kindUser, kindUser},
		"holds separator": {"a:b"},
		"leading space":   {" user"},
		"trailing space":  {"user "},
	} {
		if _, err := subject.NewKinds(declared...); err == nil {
			t.Errorf("%s (%v) was accepted", name, declared)
		}
	}
}

// Declaration order is preserved, because a screen or a log built from All
// should not reorder itself between runs.
func TestAllPreservesDeclarationOrder(t *testing.T) {
	k, err := subject.NewKinds("staff", "admin", "user")
	if err != nil {
		t.Fatal(err)
	}
	want := []subject.Kind{"staff", "admin", "user"}
	for range 20 {
		if got := k.All(); !slices.Equal(got, want) {
			t.Fatalf("All = %v, want %v", got, want)
		}
	}
}

// All returns a copy, so a caller cannot reach into the declaration and
// add a population nothing registered a loader for.
func TestAllCannotBeUsedToMutateTheDeclaration(t *testing.T) {
	k := kinds(t)
	all := k.All()
	all[0] = "tampered"
	if k.Has("tampered") {
		t.Error("mutating the slice All returned changed the declaration")
	}
	if !k.Has(kindUser) {
		t.Error("the original population is gone")
	}
}
