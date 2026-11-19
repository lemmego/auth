package auth_test

import (
	"os"
	"strings"
	"testing"
)

// auth must not require apptest, not even for tests.
//
// apptest requires auth — it boots a real application and signs requests in —
// so a test dependency the other way makes a module require cycle. Go
// permits one, and this repository already carries one between gpa and its
// drivers and has written it down as debt; adding a second to the module
// almost everything else depends on is the wrong trade.
//
// This guard exists because the obvious way to test the loader bridge
// reintroduces it: asserting that an unresolvable credential is a 401 rather
// than a 503 reads most naturally as an HTTP test, and apptest is what makes
// those pleasant. Check plus SetSubject exercises the same path with no
// cycle, which is how the rest of this package is tested — so the guard
// names the alternative rather than only forbidding the import.
func TestAuthDoesNotRequireApptest(t *testing.T) {
	raw, err := os.ReadFile("go.mod")
	if err != nil {
		t.Fatalf("reading go.mod: %v", err)
	}
	if strings.Contains(string(raw), "lemmego/apptest") {
		t.Error("go.mod requires lemmego/apptest, which requires this module — a " +
			"module require cycle.\n\n" +
			"If this came from a test wanting to assert an HTTP status code, use " +
			"Auth.Check with SetSubject and a checkContext instead: it reaches the " +
			"same classification without the dependency, and every other test in " +
			"this package is written that way.")
	}
}
