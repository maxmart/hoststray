package hosts

import (
	"slices"
	"testing"
)

func TestMovedAway(t *testing.T) {
	old := Parse("10.0.0.1 a.test\n127.0.0.1 b.test\n10.0.0.3 c.test\n#10.0.0.9 d.test\n")
	next := Parse("10.0.0.2 a.test\n10.0.0.2 b.test\n10.0.0.3 c.test\n")
	// a moved away from 10.0.0.1; b from loopback (left out); c didn't change.
	if got := MovedAway(old, next); !slices.Equal(strs(got), []string{"10.0.0.1"}) {
		t.Fatalf("got %v", got)
	}
}

func strs[T interface{ String() string }](xs []T) []string {
	var out []string
	for _, x := range xs {
		out = append(out, x.String())
	}
	return out
}
