package bitlocker

import (
	"errors"
	"testing"

	"github.com/go-encryptions/kdfbudget"
)

func threePasswords() imageSpec {
	s := defaultSpec()
	s.protectors = []protSpec{
		{prot: Password, guid: [16]byte{1}, password: "a"},
		{prot: Password, guid: [16]byte{2}, password: "b"},
		{prot: Password, guid: [16]byte{3}, password: "secret"},
	}
	return s
}

func budgetOf(work uint64) *kdfbudget.Budget {
	b := kdfbudget.Unlimited()
	b.MaxWork = work
	return b
}

// TestBudgetChargesEachDerivation: opening with the third protector runs 3
// derivations of stretchWork compressions; a budget of exactly that opens the
// volume, one unit less is refused with ErrLimit (also kdfbudget.ErrLimit).
func TestBudgetChargesEachDerivation(t *testing.T) {
	img, _ := buildImage(t, threePasswords())
	b := kdfbudget.Unlimited()
	if _, err := open(t, img, "secret", Limits{MaxKeyDerivations: 16, Budget: b}); err != nil {
		t.Fatal(err)
	}
	if got, want := b.Spent(), uint64(3*stretchWork); got != want {
		t.Fatalf("spent %d, want %d", got, want)
	}
	if _, err := open(t, img, "secret", Limits{MaxKeyDerivations: 16, Budget: budgetOf(3 * stretchWork)}); err != nil {
		t.Fatalf("a budget of exactly the work refused: %v", err)
	}
	_, err := open(t, img, "secret", Limits{MaxKeyDerivations: 16, Budget: budgetOf(3*stretchWork - 1)})
	if !errors.Is(err, ErrLimit) || !errors.Is(err, kdfbudget.ErrLimit) {
		t.Fatalf("err = %v, want ErrLimit", err)
	}
}

// TestBudgetHostileProtectorCount: a caller that raised MaxKeyDerivations to
// "no limit" is still held by the budget, and the derivations past it do not
// run.
func TestBudgetHostileProtectorCount(t *testing.T) {
	img, _ := buildImage(t, threePasswords())
	_, err := open(t, img, "wrong", Limits{MaxKeyDerivations: 1 << 30, Budget: budgetOf(stretchWork)})
	if !errors.Is(err, ErrLimit) {
		t.Fatalf("err = %v, want ErrLimit", err)
	}
}

// TestBudgetDefaultAcceptsNormalVolume: a nil Budget is a fresh default per
// Open, which a normal volume fits, over and over.
func TestBudgetDefaultAcceptsNormalVolume(t *testing.T) {
	img, _ := buildImage(t, threePasswords())
	for range 2 {
		if _, err := open(t, img, "secret", DefaultLimits); err != nil {
			t.Fatal(err)
		}
	}
}

// TestBudgetSharedIsDrained: one Budget given to two Opens caps their sum.
func TestBudgetSharedIsDrained(t *testing.T) {
	img, _ := buildImage(t, threePasswords())
	lim := Limits{MaxKeyDerivations: 16, Budget: budgetOf(5 * stretchWork)}
	if _, err := open(t, img, "secret", lim); err != nil {
		t.Fatal(err)
	}
	if _, err := open(t, img, "secret", lim); !errors.Is(err, ErrLimit) {
		t.Fatalf("second open on the same budget: err = %v, want ErrLimit", err)
	}
}
