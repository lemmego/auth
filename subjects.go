package auth

import (
	"errors"
	"fmt"

	"github.com/lemmego/api/app"

	"github.com/lemmego/auth/subject"
)

// Populations is a set of declared populations, each with a loader, behind
// one UserLoader.
//
// It lives in this package rather than in auth/subject, and the reason is
// measured rather than aesthetic: auth/subject must stay standard library
// only, because a qualified identifier is parsed by provisioning commands
// and by workers with no HTTP surface, and auth/handoff — which signs one
// into a token — would otherwise link a web framework in order to sign a
// string. Bridging to UserLoader needs app.Context, so the bridge belongs on
// this side of that line. The guard in subject/deps_test.go caught exactly
// this on its first run.
type Populations struct {
	kinds   *subject.Kinds
	loaders map[subject.Kind]KeyLoader
}

// Subjects prepares the loaders for a declared set of populations.
func Subjects(kinds *subject.Kinds) *Populations {
	return &Populations{kinds: kinds, loaders: map[subject.Kind]KeyLoader{}}
}

// Kinds returns the populations this set was built from.
func (p *Populations) Kinds() *subject.Kinds { return p.kinds }

// KeyLoader resolves one population's key to that population's user.
//
// The same contract as UserLoader, minus the qualifier: the key has
// already been parsed, and the kind has already selected this loader, so a
// loader is handed only keys of its own population and cannot be given
// somebody else's.
//
// That narrowing is the point. Written as one auth.UserLoader with a switch,
// the parsing and the dispatch live at the call site, every population's
// query sees every population's keys, and the case that forgets to return
// ErrUserNotFound authenticates nobody usefully or — worse — resolves a
// key against the wrong table.
type KeyLoader func(c app.Context, key string) (any, error)

// Register attaches a loader to a declared population.
//
// Registering a kind that was not declared is an error, not an implicit
// declaration: a typo would otherwise create a population whose credentials
// nothing else in the application knows about.
func (p *Populations) Register(kind subject.Kind, loader KeyLoader) error {
	if !p.kinds.Has(kind) {
		return fmt.Errorf("%w: %q was not declared, so nothing can issue its "+
			"credentials; add it to NewKinds", subject.ErrUnknownKind, kind)
	}
	if loader == nil {
		return fmt.Errorf("auth: the loader for the population %q is nil", kind)
	}
	if _, already := p.loaders[kind]; already {
		return fmt.Errorf("%w: %q already has a loader", subject.ErrMalformed, kind)
	}
	p.loaders[kind] = loader
	return nil
}

// MustRegister is Register for a declaration at boot.
func (p *Populations) MustRegister(kind subject.Kind, loader KeyLoader) *Populations {
	if err := p.Register(kind, loader); err != nil {
		panic(err)
	}
	return p
}

// Loaded lists the populations that have a loader, in declaration order, and
// Unloaded those that do not.
//
// Unloaded is what a boot check reads. A population with no loader cannot
// authenticate anybody, and the symptom — one group of people able to sign
// in and then refused on their next request — is one that looks like a
// session bug rather than a missing registration.
func (p *Populations) Loaded() []subject.Kind   { return p.filter(true) }
func (p *Populations) Unloaded() []subject.Kind { return p.filter(false) }

func (p *Populations) filter(loaded bool) []subject.Kind {
	var out []subject.Kind
	for _, kind := range p.kinds.All() {
		if _, has := p.loaders[kind]; has == loaded {
			out = append(out, kind)
		}
	}
	return out
}

// UserLoader is the one auth.UserLoader an application registers, whatever
// its populations.
//
// It parses the qualified identifier, selects that population's loader, and
// hands it the key. Everything it can refuse is refused as
// ErrUserNotFound rather than as a failure, and the distinction is the
// one auth's own documentation insists on: a credential nobody can resolve
// is a 401 that logs that person out, where an error is a 503 that tells
// everybody to come back shortly. A credential issued before a population
// was renamed, or one fabricated outright, is the first of those and not the
// second — reporting it as a failure would turn a stale cookie into a fake
// outage.
func (p *Populations) UserLoader() UserLoader {
	return func(c app.Context, id string) (any, error) {
		parsed, err := p.kinds.Parse(id)
		if err != nil {
			// Wrapped both ways: ErrUserNotFound is what auth acts on, and
			// the parse error is what a log needs in order to say whether
			// this was an old format or a forgery.
			return nil, fmt.Errorf("%w: %w", ErrUserNotFound, err)
		}
		loader, registered := p.loaders[parsed.Kind]
		if !registered {
			// A declared population with no loader. ErrUserNotFound, because
			// the alternative is a 503 for a configuration mistake that no
			// retry will fix — and the message names the population so the
			// cause is in the log rather than in somebody's head.
			return nil, fmt.Errorf("%w: the population %q has no loader registered",
				ErrUserNotFound, parsed.Kind)
		}
		return loader(c, parsed.Key)
	}
}

// ErrNoLoaders means no population has a loader, so nothing can
// authenticate.
var ErrNoLoaders = errors.New("auth: no population has a loader")

// Check reports whether this set of populations can authenticate anybody.
//
// Called at boot, before the application serves anything, because every
// failure it catches presents as an authentication bug rather than as a
// missing registration.
func (p *Populations) Check() error {
	if len(p.kinds.All()) == 0 {
		return fmt.Errorf("%w: no populations are declared", ErrNoLoaders)
	}
	if len(p.loaders) == 0 {
		return fmt.Errorf("%w: %d declared, none registered", ErrNoLoaders, len(p.kinds.All()))
	}
	if unloaded := p.Unloaded(); len(unloaded) > 0 {
		return fmt.Errorf("auth: %v can sign in and will be refused on the next "+
			"request, because %v %s no loader", unloaded, unloaded,
			plural(len(unloaded), "has", "have"))
	}
	return nil
}

func plural(n int, one, many string) string {
	if n == 1 {
		return one
	}
	return many
}
