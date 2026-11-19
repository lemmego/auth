package subject_test

import (
	"os/exec"
	"strings"
	"testing"
)

// subject's own vocabulary must cost a consumer nothing.
//
// The qualified identifier is written into credentials, read by a
// command-line tool that provisions accounts, and parsed by a worker that
// has no HTTP surface at all. So the parsing, the kinds and the refusing are
// standard library only.
//
// This guard found the defect it was written for on its first run. The
// loader registry started out here, importing auth for UserLoader and
// therefore api/app — and handoff, which imports this package in order to
// sign a subject into a token, transitively linked the whole web framework
// in order to compute an HMAC. It lives in auth as auth.Populations now,
// which is the side of the line app.Context belongs on.
func TestSubjectIsStandardLibraryOnly(t *testing.T) {
	for _, pkg := range deps(t, "github.com/lemmego/auth/subject") {
		// A standard-library import path has no dot in its first segment.
		// Everything else is somebody's domain name.
		first, _, _ := strings.Cut(pkg, "/")
		if strings.Contains(first, ".") {
			t.Errorf("subject reaches %s; it qualifies an identifier and must carry "+
				"nothing a provisioning command or a worker would not want — the "+
				"loader bridge belongs in auth, where app.Context already lives", pkg)
		}
	}
}

// handoff is standard library plus subject, and that is load-bearing rather
// than tidy: the token is minted by whatever host sends somebody away, which
// may be a different binary from the one that redeems it, and signing a
// string should not require linking a web framework.
//
// Written together with the guard above, which is what made the coupling
// visible: this one failed first, naming nine framework packages, and the
// cause was one import in subject rather than anything in handoff.
func TestHandoffIsStandardLibraryPlusSubject(t *testing.T) {
	allowed := map[string]bool{
		"github.com/lemmego/auth/subject": true,
	}
	for _, pkg := range deps(t, "github.com/lemmego/auth/handoff") {
		if allowed[pkg] {
			continue
		}
		// A standard-library import path has no dot in its first segment.
		first, _, _ := strings.Cut(pkg, "/")
		if strings.Contains(first, ".") {
			t.Errorf("handoff reaches %s; it must stay standard library plus "+
				"auth/subject, so a minting side with no HTTP surface can sign "+
				"a token", pkg)
		}
	}
}

func deps(t *testing.T, pkg string) []string {
	t.Helper()
	out, err := exec.Command("go", "list", "-deps", pkg).Output()
	if err != nil {
		t.Fatalf("go list -deps %s: %v", pkg, err)
	}
	var packages []string
	for _, line := range strings.Split(string(out), "\n") {
		line = strings.TrimSpace(line)
		// go list -deps includes the package itself, which is not a
		// dependency of anything.
		if line == "" || line == pkg {
			continue
		}
		packages = append(packages, line)
	}
	return packages
}
