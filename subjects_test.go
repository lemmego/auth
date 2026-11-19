package auth

import (
	"errors"
	"fmt"
	"net/http"
	"slices"
	"strings"
	"testing"

	"github.com/lemmego/api/app"

	"github.com/lemmego/auth/subject"
)

// Two populations, declared the way an application declares its own — this
// package ships no list of them.
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

// Two populations with independent primary keys, which is the situation the
// qualifier exists for: user 42 and administrator 42 are different people.
type person struct {
	Kind subject.Kind
	ID   string
}

func (p *person) GetID() string       { return subject.Of(p.Kind, p.ID).String() }
func (p *person) GetUsername() string { return string(p.Kind) + "-" + p.ID }
func (p *person) GetPassword() string { return "" }

func loaders(t *testing.T) *Populations {
	t.Helper()
	populations := Subjects(kinds(t))
	for _, kind := range []subject.Kind{kindUser, kindAdmin} {
		if err := populations.Register(kind, func(_ app.Context, key string) (any, error) {
			if key == "404" {
				return nil, ErrUserNotFound
			}
			return &person{Kind: kind, ID: key}, nil
		}); err != nil {
			t.Fatal(err)
		}
	}
	return populations
}

// resolve runs the whole path a request takes: a verified subject, the one
// UserLoader, and Check's classification of whatever comes back.
//
// Deliberately not through apptest. apptest requires auth, so a test
// dependency on it would make a module require cycle — the kind this
// repository already carries once between gpa and its drivers and has
// written down as debt. Check plus SetSubject exercises the same path, which
// is how the rest of this package's tests are written.
func resolve(t *testing.T, populations *Populations, id string) (*person, error) {
	t.Helper()
	a, ctx := newSessionAuth(t)
	a.userLoader = populations.UserLoader()

	c := newCheckContext(ctx, nil)
	SetSubject(c, id)

	if err := a.Check(c); err != nil {
		return nil, err
	}
	who, _ := UserAs[*person](c)
	return who, nil
}

// Each population's loader is handed only keys of its own population, so one
// UserLoader serves several tables without a switch at the call site.
func TestOneLoaderServesEveryPopulation(t *testing.T) {
	populations := loaders(t)

	for _, c := range []struct{ id, kind, key string }{
		{"user:42", "user", "42"},
		{"admin:42", "admin", "42"},
		{"admin:0f8c4b2a-1d3e-4f5a-9b7c-2e6d8a0f1b3c", "admin", "0f8c4b2a-1d3e-4f5a-9b7c-2e6d8a0f1b3c"},
	} {
		who, err := resolve(t, populations, c.id)
		if err != nil {
			t.Fatalf("%s: %v", c.id, err)
		}
		if who == nil {
			t.Fatalf("%s resolved to nobody", c.id)
		}
		if string(who.Kind) != c.kind || who.ID != c.key {
			t.Errorf("%s resolved to %s:%s, want %s:%s", c.id, who.Kind, who.ID, c.kind, c.key)
		}
	}
}

// The confusion the qualifier prevents, asserted rather than described: id
// 42 of one population must not resolve to id 42 of another. Both loaders
// answer for key "42", so a design that dropped the qualifier would return
// somebody — and the wrong somebody.
func TestTwoPopulationsSharingAKeyAreDifferentPeople(t *testing.T) {
	populations := loaders(t)

	asUser, err := resolve(t, populations, "user:42")
	if err != nil {
		t.Fatal(err)
	}
	asAdmin, err := resolve(t, populations, "admin:42")
	if err != nil {
		t.Fatal(err)
	}
	if asUser.Kind != kindUser || asAdmin.Kind != kindAdmin {
		t.Fatalf("user:42 resolved to %s, admin:42 to %s", asUser.Kind, asAdmin.Kind)
	}
	if *asUser == *asAdmin {
		t.Fatal("user:42 and admin:42 resolved to the same person")
	}
}

// An identifier nobody can parse is ErrUserNotFound and not a failure —
// this package's own contract. Reporting a stale credential as an error
// turns it into a fake outage: a 503 for everybody holding an old cookie.
func TestAnUnparseableIdentifierLogsSomebodyOutRatherThanFailing(t *testing.T) {
	populations := loaders(t)

	// The empty string is deliberately absent: SetSubject("") establishes no
	// subject at all, so it is refused before the loader is consulted. A
	// different and equally correct outcome, asserted on its own below
	// rather than folded in here, where it would have passed for the wrong
	// reason.
	for _, id := range []string{"42", "sysadmin:42", "user:", "user:4 2", "user:a|b"} {
		who, err := resolve(t, populations, id)
		if err == nil && who != nil {
			t.Errorf("%q authenticated %s:%s", id, who.Kind, who.ID)
			continue
		}
		if !errors.Is(err, ErrUserNotFound) {
			t.Errorf("%q gave %v, want ErrUserNotFound — an unresolvable credential "+
				"must log that person out, not report an outage", id, err)
		}
		// And it must not be classified as the store being unavailable,
		// which is the 503 half.
		var down *UserStoreUnavailableError
		if errors.As(err, &down) {
			t.Errorf("%q was reported as a store failure: %v", id, err)
		}
	}
}

// An empty identifier never reaches the loader, because nothing established
// a subject — so it is refused one step earlier. Asserted separately so that
// the test above is about the loader's classification rather than about this.
func TestAnEmptyIdentifierIsRefusedBeforeTheLoader(t *testing.T) {
	populations := Subjects(kinds(t))
	reached := false
	if err := populations.Register(kindUser, func(app.Context, string) (any, error) {
		reached = true
		return &person{Kind: kindUser, ID: "x"}, nil
	}); err != nil {
		t.Fatal(err)
	}

	who, err := resolve(t, populations, "")
	if who != nil || err == nil {
		t.Fatalf("an empty identifier authenticated %v (%v)", who, err)
	}
	if reached {
		t.Error("the loader was consulted for an empty identifier")
	}
}

// A declared population with no loader is also ErrUserNotFound and not a
// failure: no retry fixes a missing registration, and the message names the
// population so the cause is in the log rather than in somebody's head.
func TestADeclaredPopulationWithNoLoaderRefusesRatherThanFails(t *testing.T) {
	populations := Subjects(kinds(t))
	if err := populations.Register(kindUser, func(_ app.Context, key string) (any, error) {
		return &person{Kind: kindUser, ID: key}, nil
	}); err != nil {
		t.Fatal(err)
	}

	if _, err := resolve(t, populations, "user:42"); err != nil {
		t.Fatalf("the registered population was refused: %v", err)
	}

	who, err := resolve(t, populations, "admin:42")
	if who != nil {
		t.Fatalf("a population with no loader authenticated %s:%s", who.Kind, who.ID)
	}
	if !errors.Is(err, ErrUserNotFound) {
		t.Errorf("err = %v, want ErrUserNotFound", err)
	}
	var down *UserStoreUnavailableError
	if errors.As(err, &down) {
		t.Errorf("a missing registration was reported as a store failure: %v", err)
	}
	if err == nil || !strings.Contains(err.Error(), "admin") {
		t.Errorf("the error does not name the population: %v", err)
	}
}

// A store that genuinely could not answer is still a 503, so a database blip
// does not log everybody out and then stampede the login page.
func TestAStoreFailureIsNotAuthenticationFailure(t *testing.T) {
	populations := Subjects(kinds(t))
	unreachable := fmt.Errorf("the database is unreachable")
	for _, kind := range []subject.Kind{kindUser, kindAdmin} {
		// Any error that is NOT ErrUserNotFound, which is how this package's
		// contract says a loader reports that the store could not answer.
		if err := populations.Register(kind, func(app.Context, string) (any, error) {
			return nil, unreachable
		}); err != nil {
			t.Fatal(err)
		}
	}

	_, err := resolve(t, populations, "user:42")
	var down *UserStoreUnavailableError
	if !errors.As(err, &down) {
		t.Fatalf("a store failure gave %v, want a UserStoreUnavailableError — a "+
			"blip must not log everybody out", err)
	}
	if down.Status != http.StatusServiceUnavailable {
		t.Errorf("status = %d, want 503", down.Status)
	}
	if errors.Is(err, ErrUserNotFound) {
		t.Error("a store failure was also reported as a missing user")
	}
}

// A loader may still report a genuinely absent person, which is the 401 that
// logs them out.
func TestAnAbsentPersonLogsThemOut(t *testing.T) {
	who, err := resolve(t, loaders(t), "user:404")
	if who != nil {
		t.Fatal("a deleted account authenticated")
	}
	if !errors.Is(err, ErrUserNotFound) {
		t.Fatalf("err = %v, want ErrUserNotFound", err)
	}
}

func TestRegistrationRefusesWhatCannotWork(t *testing.T) {
	populations := Subjects(kinds(t))
	loader := func(app.Context, string) (any, error) { return nil, nil }

	// A population that was not declared: an implicit declaration here would
	// create a population whose credentials nothing else in the application
	// knows about.
	if err := populations.Register("sysadmin", loader); !errors.Is(err, subject.ErrUnknownKind) {
		t.Errorf("an undeclared population was registered: %v", err)
	}
	if err := populations.Register(kindUser, nil); err == nil {
		t.Error("a nil loader was registered")
	}
	if err := populations.Register(kindUser, loader); err != nil {
		t.Fatal(err)
	}
	if err := populations.Register(kindUser, loader); err == nil {
		t.Error("a second loader for one population was registered")
	}
}

// What a boot check reads. A population that can sign in and is refused on
// its next request looks like a session bug rather than a missing
// registration, which is why this is asserted at boot instead.
func TestCheckNamesThePopulationsThatCannotAuthenticate(t *testing.T) {
	none, err := subject.NewKinds()
	if err != nil {
		t.Fatal(err)
	}
	if err := Subjects(none).Check(); !errors.Is(err, ErrNoLoaders) {
		t.Errorf("no populations at all: %v, want ErrNoLoaders", err)
	}

	declared := Subjects(kinds(t))
	if err := declared.Check(); !errors.Is(err, ErrNoLoaders) {
		t.Errorf("declared but unregistered: %v, want ErrNoLoaders", err)
	}

	loader := func(app.Context, string) (any, error) { return nil, nil }
	if err := declared.Register(kindUser, loader); err != nil {
		t.Fatal(err)
	}
	err = declared.Check()
	if err == nil {
		t.Fatal("a half-registered set of populations passed the boot check")
	}
	if !strings.Contains(err.Error(), "admin") {
		t.Errorf("the error does not name the unloaded population: %v", err)
	}
	if !slices.Equal(declared.Unloaded(), []subject.Kind{kindAdmin}) {
		t.Errorf("Unloaded = %v, want [admin]", declared.Unloaded())
	}
	if !slices.Equal(declared.Loaded(), []subject.Kind{kindUser}) {
		t.Errorf("Loaded = %v, want [user]", declared.Loaded())
	}

	if err := declared.Register(kindAdmin, loader); err != nil {
		t.Fatal(err)
	}
	if err := declared.Check(); err != nil {
		t.Errorf("a fully registered set failed the boot check: %v", err)
	}
}
