package handoff_test

import (
	"context"
	"encoding/base64"
	"errors"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/lemmego/auth/handoff"
	"github.com/lemmego/auth/subject"
)

const (
	secret   = "a-signing-key-long-enough-to-be-accepted"
	acme     = "0f8c4b2a-1d3e-4f5a-9b7c-2e6d8a0f1b3c"
	globex   = "7a1b2c3d-4e5f-4a6b-8c9d-0e1f2a3b4c5d"
	adminKey = "c1d2e3f4-0000-4aaa-8bbb-ccccddddeeee"
)

// Two populations, declared the way an application declares its own — this
// package ships no list of them.
const (
	kindAdmin    subject.Kind = "admin"
	kindCustomer subject.Kind = "customer"
)

func kinds(t *testing.T) *subject.Kinds {
	t.Helper()
	k, err := subject.NewKinds(kindAdmin, kindCustomer)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func admin() subject.Subject { return subject.Of(kindAdmin, adminKey) }

func signer(t *testing.T, options ...handoff.Option) *handoff.Signer {
	t.Helper()
	s, err := handoff.NewSigner(secret, kinds(t), options...)
	if err != nil {
		t.Fatalf("NewSigner: %v", err)
	}
	return s
}

func TestAMintedTokenVerifiesOnce(t *testing.T) {
	s := signer(t)
	store := handoff.NewMemoryStore()
	want := admin()

	token, minted, err := s.Mint(want, acme)
	if err != nil {
		t.Fatalf("Mint: %v", err)
	}

	grant, err := s.Verify(context.Background(), token, acme, store)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if grant.Subject != want {
		t.Errorf("subject = %+v, want %+v", grant.Subject, want)
	}
	if grant.Audience != acme {
		t.Errorf("audience = %q, want %q", grant.Audience, acme)
	}
	if grant.ID != minted.ID {
		t.Errorf("id = %q, want the minted %q", grant.ID, minted.ID)
	}
}

// The property the whole package exists for.
func TestAReplayIsRefused(t *testing.T) {
	s := signer(t)
	store := handoff.NewMemoryStore()

	token, _, err := s.Mint(admin(), acme)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.Verify(context.Background(), token, acme, store); err != nil {
		t.Fatalf("first use: %v", err)
	}
	if _, err := s.Verify(context.Background(), token, acme, store); !errors.Is(err, handoff.ErrUsed) {
		t.Fatalf("second use: %v, want ErrUsed", err)
	}
}

// A token is bound to one audience, so acme's link is worthless at globex.
//
// And the second half is the one a careless implementation gets wrong: the
// refused attempt must NOT have consumed the token, so the legitimate
// redemption still works afterwards. Otherwise one mistyped host — or one
// security scanner following the link — permanently breaks a link whose
// owner has not clicked it yet.
func TestATokenForAnotherAudienceIsRefusedWithoutBurningIt(t *testing.T) {
	s := signer(t)
	store := handoff.NewMemoryStore()

	token, _, err := s.Mint(admin(), acme)
	if err != nil {
		t.Fatal(err)
	}

	if _, err := s.Verify(context.Background(), token, globex, store); !errors.Is(err, handoff.ErrWrongAudience) {
		t.Fatalf("at the wrong audience: %v, want ErrWrongAudience", err)
	}
	if _, err := s.Verify(context.Background(), token, acme, store); err != nil {
		t.Fatalf("the refusal burned the token: %v", err)
	}
}

func TestAnExpiredTokenIsRefusedWithoutBurningIt(t *testing.T) {
	now := time.Now()
	clock := func() time.Time { return now }
	s := signer(t, handoff.WithTTL(time.Minute), handoff.WithClock(func() time.Time { return clock() }))
	store := handoff.NewMemoryStore()

	token, _, err := s.Mint(admin(), acme)
	if err != nil {
		t.Fatal(err)
	}

	now = now.Add(2 * time.Minute)
	if _, err := s.Verify(context.Background(), token, acme, store); !errors.Is(err, handoff.ErrExpired) {
		t.Fatalf("expired token: %v, want ErrExpired", err)
	}

	// Same reasoning as the wrong-workspace case: a refusal that consumes
	// the token would mean a token could be destroyed by anybody who can
	// make a request after it expires, which is everybody.
	now = now.Add(-2 * time.Minute)
	if _, err := s.Verify(context.Background(), token, acme, store); err != nil {
		t.Fatalf("the expiry check burned the token: %v", err)
	}
}

// Every field of the payload must be covered by the signature. These are
// constructed by taking a genuine token apart, changing one claim, and
// putting the original signature back — which is the forgery a signature
// over anything less than the whole payload would admit.
func TestEveryClaimIsSigned(t *testing.T) {
	s := signer(t)

	token, grant, err := s.Mint(admin(), acme)
	if err != nil {
		t.Fatal(err)
	}
	version, payload, mac := split(t, token)
	fields := strings.Split(string(decode(t, payload)), "|")
	if len(fields) != 4 {
		t.Fatalf("payload has %d fields: %q", len(fields), fields)
	}

	for name, mutate := range map[string]func([]string){
		"the token id": func(f []string) { f[0] = "deadbeefdeadbeefdeadbeefdeadbeef" },
		"the audience": func(f []string) { f[1] = globex },
		"the subject":  func(f []string) { f[2] = subject.Of(kindCustomer, "1").String() },
		"the expiry": func(f []string) {
			f[3] = strconv.FormatInt(grant.ExpiresAt.Add(time.Hour).Unix(), 10)
		},
	} {
		changed := append([]string(nil), fields...)
		mutate(changed)
		forged := version + "." + encode(strings.Join(changed, "|")) + "." + mac

		_, err := s.Verify(context.Background(), forged, acme, handoff.NewMemoryStore())
		if !errors.Is(err, handoff.ErrSignature) {
			t.Errorf("changing %s gave %v, want ErrSignature", name, err)
		}
	}
}

// A token claiming another version is refused by the prefix check.
//
// This test cannot distinguish the prefix check from the signature covering
// the version, because against one signer there is no token whose signature
// would verify under a different prefix. It is named for what it proves
// rather than for the stronger property, because a test whose name
// overstates it is how an untested guarantee ends up believed — and the
// stronger property has its own test now, since WithVersion made it
// reachable.
func TestATokenOfAnotherVersionIsRefused(t *testing.T) {
	s := signer(t)
	token, _, err := s.Mint(admin(), acme)
	if err != nil {
		t.Fatal(err)
	}
	_, payload, mac := split(t, token)

	for _, version := range []string{"lmgh2", "LMGH1", ""} {
		_, err := s.Verify(context.Background(), version+"."+payload+"."+mac, acme, handoff.NewMemoryStore())
		if err == nil {
			t.Errorf("version %q was accepted", version)
		}
	}
}

func TestATokenFromAnotherKeyIsRefused(t *testing.T) {
	mine := signer(t)
	theirs, err := handoff.NewSigner("a-completely-different-key-of-sufficient-length", kinds(t))
	if err != nil {
		t.Fatal(err)
	}

	token, _, err := theirs.Mint(admin(), acme)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := mine.Verify(context.Background(), token, acme, handoff.NewMemoryStore()); !errors.Is(err, handoff.ErrSignature) {
		t.Fatalf("a foreign token gave %v, want ErrSignature", err)
	}
}

func TestRubbishIsRefused(t *testing.T) {
	s := signer(t)
	for _, token := range []string{
		"", ".", "..", "lmgh1", "lmgh1.", "lmgh1..", "lmgh1.x", "not-a-token",
		"lmgh1.!!!.!!!", strings.Repeat("a", 5000),
	} {
		if _, err := s.Verify(context.Background(), token, acme, handoff.NewMemoryStore()); err == nil {
			t.Errorf("%q was accepted", token)
		}
	}
}

// Two tokens must never share an id, or redeeming one would burn the other.
func TestEveryTokenHasItsOwnIdentifier(t *testing.T) {
	s := signer(t)
	seen := map[string]bool{}
	for range 200 {
		_, grant, err := s.Mint(admin(), acme)
		if err != nil {
			t.Fatal(err)
		}
		if seen[grant.ID] {
			t.Fatalf("id %q was minted twice", grant.ID)
		}
		seen[grant.ID] = true
	}
}

func TestASignerRefusesAConfigurationItCannotHonour(t *testing.T) {
	if _, err := handoff.NewSigner("short", kinds(t)); !errors.Is(err, handoff.ErrWeakSecret) {
		t.Errorf("a short secret: %v, want ErrWeakSecret", err)
	}
	if _, err := handoff.NewSigner("", kinds(t)); !errors.Is(err, handoff.ErrWeakSecret) {
		t.Errorf("an empty secret: %v, want ErrWeakSecret", err)
	}
	if _, err := handoff.NewSigner(secret, kinds(t), handoff.WithTTL(0)); err == nil {
		t.Error("a zero ttl was accepted")
	}
	if _, err := handoff.NewSigner(secret, kinds(t), handoff.WithTTL(-time.Second)); err == nil {
		t.Error("a negative ttl was accepted")
	}
	if _, err := handoff.NewSigner(secret, kinds(t), handoff.WithTTL(handoff.MaxTTL+time.Second)); err == nil {
		t.Errorf("a ttl over the %s maximum was accepted", handoff.MaxTTL)
	}
	if _, err := handoff.NewSigner(secret, kinds(t), handoff.WithTTL(handoff.MaxTTL)); err != nil {
		t.Errorf("the maximum ttl itself was refused: %v", err)
	}
}

// A nil store is a token that can be replayed, which is the one thing this
// package guarantees against. It must be an error and not a quiet pass.
func TestVerifyingWithNoStoreIsAnError(t *testing.T) {
	s := signer(t)
	token, _, err := s.Mint(admin(), acme)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.Verify(context.Background(), token, acme, nil); err == nil {
		t.Fatal("verification with no store succeeded, so the token is replayable")
	}
}

func TestMintRefusesWhatItCannotSignMeaningfully(t *testing.T) {
	s := signer(t)
	if _, _, err := s.Mint(subject.Subject{}, acme); err == nil {
		t.Error("a token for nobody was minted")
	}
	for _, audience := range []string{"", "acme|globex", "with space", strings.Repeat("x", 100)} {
		if _, _, err := s.Mint(admin(), audience); err == nil {
			t.Errorf("a token for audience %q was minted", audience)
		}
	}
	// And a population this application does not have is refused at the
	// mint, not at the redemption — a mistake caught here is a failed
	// redirect, where the same mistake caught at the redemption is a person
	// who cannot sign in and a token already burned.
	if _, _, err := s.Mint(subject.Of("nosuchkind", "1"), acme); !errors.Is(err, subject.ErrUnknownKind) {
		t.Errorf("an undeclared population was minted: %v", err)
	}
}

// The token carries the population, so a handoff minted for an
// administrator cannot be redeemed as a customer. The verifier returns the
// subject and the caller checks it — which is what MustMatch is for.
func TestTheTokenNamesItsPopulation(t *testing.T) {
	s := signer(t)
	token, _, err := s.Mint(admin(), acme)
	if err != nil {
		t.Fatal(err)
	}
	grant, err := s.Verify(context.Background(), token, acme, handoff.NewMemoryStore())
	if err != nil {
		t.Fatal(err)
	}
	if err := grant.Subject.MustMatch(kindCustomer); err == nil {
		t.Error("an administrator handoff passed a customer requirement")
	}
	if err := grant.Subject.MustMatch(kindAdmin); err != nil {
		t.Errorf("an administrator handoff failed an administrator requirement: %v", err)
	}
}

func TestTheMemoryStoreIsFirstComeFirstServed(t *testing.T) {
	store := handoff.NewMemoryStore()
	expiry := time.Now().Add(time.Minute)

	first, err := store.Consume(context.Background(), "abc", expiry)
	if err != nil || !first {
		t.Fatalf("first consume: %v, %v", first, err)
	}
	second, err := store.Consume(context.Background(), "abc", expiry)
	if err != nil || second {
		t.Fatalf("second consume: %v, %v", second, err)
	}
	// A different id is unaffected.
	other, err := store.Consume(context.Background(), "def", expiry)
	if err != nil || !other {
		t.Fatalf("a different id: %v, %v", other, err)
	}
}

func split(t *testing.T, token string) (version, payload, mac string) {
	t.Helper()
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		t.Fatalf("token has %d parts: %q", len(parts), token)
	}
	return parts[0], parts[1], parts[2]
}

func decode(t *testing.T, s string) []byte {
	t.Helper()
	raw, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil {
		t.Fatalf("decode %q: %v", s, err)
	}
	return raw
}

func encode(s string) string { return base64.RawURLEncoding.EncodeToString([]byte(s)) }

// The audience comparison is exact, not a prefix match.
//
// This test exists because a probe found the gap: replacing hmac.Equal with
// strings.HasPrefix left the whole suite green, since every audience in it
// is a uuid and no uuid is a prefix of another. A prefix match is only
// exploitable between audiences where one IS a prefix of the other — the
// shape slugs have, and slugs are what most applications put in a hostname.
func TestAnAudienceIsMatchedExactlyAndNotByPrefix(t *testing.T) {
	s := signer(t)

	// "acme" is a prefix of "acme2", which is the pair a prefix match
	// confuses and an exact comparison does not.
	token, _, err := s.Mint(admin(), "acme")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.Verify(context.Background(), token, "acme2", handoff.NewMemoryStore()); !errors.Is(err, handoff.ErrWrongAudience) {
		t.Errorf("a token for acme was accepted at acme2: %v", err)
	}

	// And the other direction, in case somebody compares the arguments the
	// other way round.
	wider, _, err := s.Mint(admin(), "acme2")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.Verify(context.Background(), wider, "acme", handoff.NewMemoryStore()); !errors.Is(err, handoff.ErrWrongAudience) {
		t.Errorf("a token for acme2 was accepted at acme: %v", err)
	}

	// The exact match still works, so this is not simply refusing everything.
	if _, err := s.Verify(context.Background(), token, "acme", handoff.NewMemoryStore()); err != nil {
		t.Errorf("the exact audience was refused: %v", err)
	}
}

// The version is covered by the SIGNATURE and not only checked as a prefix.
//
// TestATokenOfAnotherVersionIsRefused says in its own comment that it cannot
// distinguish the two, because with one version there is no token whose
// signature would verify under a different prefix. WithVersion makes the
// distinction testable: mint under one version, rewrite the prefix to
// another, and present it to a signer configured for that other version with
// the same key. If the signature covered only the payload, the MAC would
// verify and the prefix check would pass — a token minted for one
// application's handoff, replayed into another's.
//
// A probe confirmed the gap was real: signing only the payload left the
// whole suite green.
func TestTheVersionIsSignedAndNotMerelyChecked(t *testing.T) {
	const (
		mine   = "appa1"
		theirs = "appb1"
	)
	minter, err := handoff.NewSigner(secret, kinds(t), handoff.WithVersion(mine))
	if err != nil {
		t.Fatal(err)
	}
	// The same signing key, a different version: two handoffs in one
	// application, or two applications sharing a secret.
	other, err := handoff.NewSigner(secret, kinds(t), handoff.WithVersion(theirs))
	if err != nil {
		t.Fatal(err)
	}

	token, _, err := minter.Mint(admin(), acme)
	if err != nil {
		t.Fatal(err)
	}
	_, payload, mac := split(t, token)
	relabelled := theirs + "." + payload + "." + mac

	if _, err := other.Verify(context.Background(), relabelled, acme, handoff.NewMemoryStore()); !errors.Is(err, handoff.ErrSignature) {
		t.Fatalf("a token relabelled from %s to %s verified: %v — the version is "+
			"not covered by the signature", mine, theirs, err)
	}

	// And the genuine article still verifies under its own version, so the
	// refusal above is about the relabelling rather than about the key.
	if _, err := minter.Verify(context.Background(), token, acme, handoff.NewMemoryStore()); err != nil {
		t.Errorf("the original token was refused by its own signer: %v", err)
	}
}
