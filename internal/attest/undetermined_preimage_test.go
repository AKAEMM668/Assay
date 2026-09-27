package attest_test

import (
	"errors"
	"strings"
	"testing"

	"github.com/use-assay/assay/internal/attest"
	"github.com/use-assay/assay/internal/mechanics"
)

// TestUndeterminedStaysOutOfPreimage pins the #43 decision: the undetermined
// flag is deliberately NOT part of the evidence_hash preimage.
//
// The argument, stated in docs/contract-interface.md next to the encoding: an
// undetermined report can never be attested — attest.FromReport refuses it
// with ErrUndetermined — so across everything that is attestable the flag is
// constant (false) and commits nothing. Adding it would only change bytes
// without strengthening the hash. The guarantee therefore rests on FromReport
// refusing, which is enforced in one function; the companion test,
// TestFromReportStillRefusesUndetermined below, is the link that keeps the
// documented argument true. If that refusal ever moves or weakens, this pair
// must be revisited together with a PreimageVersion bump decision.
func TestUndeterminedStaysOutOfPreimage(t *testing.T) {
	base := report(func(r *mechanics.Report) {})

	withFlag := report(func(r *mechanics.Report) {
		r.Undetermined = true
		r.UndeterminedChecks = []string{"reputation"}
	})

	if got, want := attest.Preimage(withFlag), attest.Preimage(base); got != want {
		t.Fatalf("preimage changed when only undetermined was set:\n got %q\nwant %q", got, want)
	}
	if strings.Contains(attest.Preimage(withFlag), "undetermined") {
		t.Fatal("preimage mentions undetermined; the decision is exclusion")
	}
}

// TestFromReportStillRefusesUndetermined is the load-bearing half of the #43
// decision: the hash excludes the flag precisely because every undetermined
// report is refused before it can be attested. This asserts that refusal still
// holds, so the documented reasoning in docs/contract-interface.md stays true.
func TestFromReportStillRefusesUndetermined(t *testing.T) {
	rep := report(func(r *mechanics.Report) {
		r.Undetermined = true
		r.UndeterminedChecks = []string{"reputation"}
	})
	_, err := attest.FromReport(rep)
	if err == nil {
		t.Fatal("FromReport accepted an undetermined report; the #43 exclusion argument no longer holds")
	}
	if !errors.Is(err, attest.ErrUndetermined) {
		t.Fatalf("err = %v, want ErrUndetermined", err)
	}
}
