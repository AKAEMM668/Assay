package mechanics_test

import (
	"context"
	"testing"
	"time"

	"github.com/use-assay/assay/internal/horizon"
	"github.com/use-assay/assay/internal/mechanics"
	"github.com/use-assay/assay/internal/sep1"
)

// The evidence shape for a SEP-1 claim has to make a redirect visible. The
// requested location comes from home_domain (attacker-controlled); the final
// location is where the document was actually read. Recording only one of them
// leaves an auditor unable to tell which URL a claim refers to.

func tomlEvidence(t *testing.T, f mechanics.Finding) mechanics.Evidence {
	t.Helper()
	for _, e := range f.Evidence {
		if e.Source == "stellar.toml" {
			return e
		}
	}
	t.Fatalf("no stellar.toml evidence in finding: %+v", f.Evidence)
	return mechanics.Evidence{}
}

// TestDomainEvidenceRecordsRequestedAndFinalURLs covers the success path where a
// same-site redirect moved the fetch: URL is the final location and
// RequestedURL is the one home_domain pointed at, and the two differ.
func TestDomainEvidenceRecordsRequestedAndFinalURLs(t *testing.T) {
	const requested = "https://circle.com/.well-known/stellar.toml"
	const final = "https://www.circle.com/.well-known/stellar.toml"
	fetched := time.Date(2026, 9, 27, 12, 0, 0, 0, time.UTC)

	s := &mechanics.Subject{
		Asset:  mechanics.Asset{Code: "USDC", Issuer: testIssuer},
		Issuer: &horizon.Account{AccountID: testIssuer, HomeDomain: "circle.com"},
		Toml: &sep1.Doc{
			URL:        final,
			FetchedAt:  fetched,
			Currencies: []sep1.Currency{{Code: "USDC", Issuer: testIssuer}},
		},
		TomlURL: requested,
	}

	f, err := mechanics.DomainCheck{}.Run(context.Background(), s)
	if err != nil {
		t.Fatalf("DomainCheck.Run: %v", err)
	}
	if f.Accountability == nil || *f.Accountability != mechanics.AccountabilityVerified {
		t.Fatalf("accountability = %v, want verified", f.Accountability)
	}

	ev := tomlEvidence(t, f)
	if ev.URL != final {
		t.Errorf("evidence URL = %q, want the final location %q", ev.URL, final)
	}
	if ev.RequestedURL != requested {
		t.Errorf("evidence RequestedURL = %q, want the requested location %q; without it a redirect is invisible", ev.RequestedURL, requested)
	}
}

// TestDomainEvidenceRecordsBothURLsOnFailure covers the failure path: no final
// document exists, so both fields carry the requested location, and the
// evidence is labelled Attempted rather than as an answer. The distinction is
// programmatic, not left to English.
func TestDomainEvidenceRecordsBothURLsOnFailure(t *testing.T) {
	const requested = "https://circle.com/.well-known/stellar.toml"
	attempted := time.Date(2026, 9, 27, 12, 0, 0, 0, time.UTC)

	s := &mechanics.Subject{
		Asset:           mechanics.Asset{Code: "USDC", Issuer: testIssuer},
		Issuer:          &horizon.Account{AccountID: testIssuer, HomeDomain: "circle.com"},
		TomlURL:         requested,
		TomlErr:         "sep1: fetch https://circle.com/.well-known/stellar.toml: status 404",
		TomlAttemptedAt: attempted,
	}

	f, err := mechanics.DomainCheck{}.Run(context.Background(), s)
	if err != nil {
		t.Fatalf("DomainCheck.Run: %v", err)
	}
	if f.Accountability == nil || *f.Accountability != mechanics.AccountabilityUnverified {
		t.Fatalf("accountability = %v, want unverified", f.Accountability)
	}

	ev := tomlEvidence(t, f)
	if ev.URL != requested {
		t.Errorf("failure evidence URL = %q, want the requested location %q", ev.URL, requested)
	}
	if ev.RequestedURL != requested {
		t.Errorf("failure evidence RequestedURL = %q, want the requested location %q", ev.RequestedURL, requested)
	}
	if !ev.Attempted {
		t.Error("failure evidence is not marked Attempted: an attempt is not an answer")
	}
}
