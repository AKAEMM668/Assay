package mechanics_test

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/use-assay/assay/internal/horizon"
	"github.com/use-assay/assay/internal/mechanics"
	"github.com/use-assay/assay/internal/sep1"
	"github.com/use-assay/assay/internal/stellarexpert"
)

// loadSubject rebuilds a Subject from captured fixtures, using the same
// decoders the live fetchers use. Nothing here touches the network.
func loadSubject(t *testing.T, dir string) *mechanics.Subject {
	t.Helper()
	base := filepath.Join("testdata", dir)

	var stat horizon.AssetStat
	readJSON(t, filepath.Join(base, "asset.json"), &stat)
	var acct horizon.Account
	readJSON(t, filepath.Join(base, "account.json"), &acct)

	s := &mechanics.Subject{
		Asset:     mechanics.Asset{Code: stat.AssetCode, Issuer: stat.AssetIssuer},
		Stat:      &stat,
		Issuer:    &acct,
		FetchedAt: capturedAt(t, base),
	}

	if acct.HomeDomain != "" {
		s.TomlURL = sep1.URLFor(acct.HomeDomain)
	}
	if b, err := os.ReadFile(filepath.Join(base, "stellar.toml")); err == nil {
		doc, err := sep1.Parse(b)
		if err != nil {
			t.Fatalf("parse %s stellar.toml: %v", dir, err)
		}
		doc.URL = s.TomlURL
		s.Toml = doc
	} else if st, err := os.ReadFile(filepath.Join(base, "stellar.toml.status")); err == nil {
		s.TomlErr = "status " + strings.TrimSpace(string(st))
	}

	if _, err := os.Stat(filepath.Join(base, "directory.json")); err == nil {
		var e stellarexpert.DirectoryEntry
		readJSON(t, filepath.Join(base, "directory.json"), &e)
		s.Directory = &e
		s.DirectoryURL = "https://api.stellar.expert/explorer/directory/" + stat.AssetIssuer
	}
	if _, err := os.Stat(filepath.Join(base, "blocked.json")); err == nil {
		var b stellarexpert.BlockedDomain
		readJSON(t, filepath.Join(base, "blocked.json"), &b)
		s.Blocked = &b
	}
	return s
}

// capturedAt returns the capture date recorded for a fixture directory. The
// original sweep recorded no per-directory date, so those directories keep the
// 2026-08-10 date stated in testdata/PROVENANCE.md; a later capture writes
// `captured.date` so evidence retrieval times in a report agree with the
// provenance instead of inheriting the date of the first sweep.
func capturedAt(t *testing.T, base string) time.Time {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(base, "captured.date"))
	if err != nil {
		return time.Date(2026, 8, 10, 0, 0, 0, 0, time.UTC)
	}
	d, err := time.Parse("2006-01-02", strings.TrimSpace(string(b)))
	if err != nil {
		t.Fatalf("parse %s/captured.date: %v", base, err)
	}
	return d
}

func readJSON(t *testing.T, path string, out any) {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	if err := json.Unmarshal(b, out); err != nil {
		t.Fatalf("decode %s: %v", path, err)
	}
}

// TestEval is the judgment eval. Detecting a flag is deterministic and
// uninteresting; what these cases measure is whether the severity model
// separates a trap from a legitimate compliance feature, and whether
// escalation fires only on reputation.
//
// See docs/eval.md for the labelling rationale for each subject.
func TestEval(t *testing.T) {
	cases := []struct {
		dir string
		// why states what this subject is supposed to prove.
		why string

		wantBase      mechanics.Severity
		wantSeverity  mechanics.Severity
		wantEscalated bool
		wantAccount   mechanics.Accountability
	}{
		{
			dir:          "aqua-clear-verified",
			why:          "no auth flags at all: the issuer has no power over holders, and a reciprocal domain confirms who it is",
			wantBase:     mechanics.Clear,
			wantSeverity: mechanics.Clear,
			wantAccount:  mechanics.AccountabilityVerified,
		},
		{
			dir:          "shx-clear-flagslocked",
			why:          "no auth flags AND auth_immutable: the issuer can never add freeze or clawback later",
			wantBase:     mechanics.Clear,
			wantSeverity: mechanics.Clear,
			wantAccount:  mechanics.AccountabilityVerified,
		},
		{
			dir: "usdc-revocable-regulated",
			why: "a real regulated stablecoin that legitimately uses auth_revocable. It must report " +
				"freeze-capable (medium) on the strength of the flag alone: not discounted to clear " +
				"because Circle issues it, and not escalated because nothing flags it.",
			wantBase:     mechanics.Medium,
			wantSeverity: mechanics.Medium,
			// circle.com does not serve a stellar.toml, so the reciprocal claim
			// genuinely fails. Reported honestly rather than special-cased.
			wantAccount: mechanics.AccountabilityUnverified,
		},
		{
			dir: "berkshire-clawback-scam",
			why: "impersonation asset with clawback: capability alone puts it at high, and the curated " +
				"malicious tag escalates it to critical",
			wantBase:      mechanics.High,
			wantSeverity:  mechanics.Critical,
			wantEscalated: true,
			wantAccount:   mechanics.AccountabilityUnverified,
		},
		{
			dir: "doge-noflags-scam",
			why: "the case that justifies keeping reputation as a separate upward-only axis: a known " +
				"scam asset carrying NO auth flags. Capability is honestly clear, and escalation is " +
				"the only thing that catches it.",
			wantBase:      mechanics.Clear,
			wantSeverity:  mechanics.Critical,
			wantEscalated: true,
			wantAccount:   mechanics.AccountabilityUnverified,
		},
		{
			dir: "velo-no-home-domain",
			why: "no home_domain at all: nobody has claimed the asset, so accountability is " +
				"unknown rather than unverified. Its flags are identical to aqua-clear-verified, " +
				"so its severity must be identical too — absence of a claim is not a failed one.",
			wantBase:     mechanics.Clear,
			wantSeverity: mechanics.Clear,
			wantAccount:  mechanics.AccountabilityUnknown,
		},
	}

	eng := mechanics.NewEngine()
	for _, tc := range cases {
		t.Run(tc.dir, func(t *testing.T) {
			s := loadSubject(t, tc.dir)
			rep, err := eng.Run(context.Background(), s)
			if err != nil {
				t.Fatalf("run: %v", err)
			}
			if rep.Base != tc.wantBase {
				t.Errorf("base severity = %v, want %v\nwhy this case exists: %s",
					rep.Base, tc.wantBase, tc.why)
			}
			if rep.Severity != tc.wantSeverity {
				t.Errorf("severity = %v, want %v\nwhy this case exists: %s",
					rep.Severity, tc.wantSeverity, tc.why)
			}
			if rep.Escalated != tc.wantEscalated {
				t.Errorf("escalated = %v, want %v", rep.Escalated, tc.wantEscalated)
			}
			if rep.Accountability != tc.wantAccount {
				t.Errorf("accountability = %v, want %v", rep.Accountability, tc.wantAccount)
			}
		})
	}
}

// TestAccountabilityNeverChangesSeverity is the property the whole model rests
// on. Two subjects with identical issuer flags must classify identically no
// matter how well attributed they are, or a contract gating on severity is
// relying on someone's opinion instead of on ledger mechanics.
func TestAccountabilityNeverChangesSeverity(t *testing.T) {
	eng := mechanics.NewEngine()

	verified := loadSubject(t, "aqua-clear-verified")
	anonymous := loadSubject(t, "aqua-clear-verified")
	// Strip every trace of attribution, leaving the flags untouched.
	anonymous.Issuer.HomeDomain = ""
	anonymous.Toml = nil
	anonymous.Directory = nil
	anonymous.Blocked = nil

	repV, err := eng.Run(context.Background(), verified)
	if err != nil {
		t.Fatal(err)
	}
	repA, err := eng.Run(context.Background(), anonymous)
	if err != nil {
		t.Fatal(err)
	}

	if repV.Severity != repA.Severity {
		t.Errorf("attribution changed severity: verified=%v anonymous=%v",
			repV.Severity, repA.Severity)
	}
	if repV.Accountability == repA.Accountability {
		t.Errorf("accountability should differ between the two subjects, both = %v",
			repV.Accountability)
	}
}

// TestNoHomeDomainIsUnknownNotUnverified is the distinction issue #3 asks for,
// asserted against a real capture rather than a stripped copy: VELO's issuer
// account carries no home_domain at all (Horizon omits the field entirely), so
// nobody has claimed the asset. That is a different state from a domain that
// was advertised and failed verification, and it must not move severity either
// — aqua-clear-verified is the same flags with a claim on top.
func TestNoHomeDomainIsUnknownNotUnverified(t *testing.T) {
	eng := mechanics.NewEngine()

	unclaimed, err := eng.Run(context.Background(), loadSubject(t, "velo-no-home-domain"))
	if err != nil {
		t.Fatal(err)
	}
	claimed, err := eng.Run(context.Background(), loadSubject(t, "aqua-clear-verified"))
	if err != nil {
		t.Fatal(err)
	}

	if unclaimed.Accountability != mechanics.AccountabilityUnknown {
		t.Errorf("accountability = %q, want %q: an issuer with no home_domain has made no "+
			"claim, it has not failed one", unclaimed.Accountability, mechanics.AccountabilityUnknown)
	}
	if claimed.Accountability != mechanics.AccountabilityVerified {
		t.Errorf("control subject accountability = %q, want %q",
			claimed.Accountability, mechanics.AccountabilityVerified)
	}
	if unclaimed.Base != claimed.Base || unclaimed.Severity != claimed.Severity {
		t.Errorf("identical flags classified differently: no home_domain = %v/%v, verified domain = %v/%v",
			unclaimed.Base, unclaimed.Severity, claimed.Base, claimed.Severity)
	}

	var domain *mechanics.Finding
	for i := range unclaimed.Findings {
		if unclaimed.Findings[i].Check == "sep1-domain" {
			domain = &unclaimed.Findings[i]
		}
	}
	if domain == nil {
		t.Fatal("report carries no sep1-domain finding")
	}
	for _, want := range []string{"Nobody has publicly claimed", "not a failed verification"} {
		if !strings.Contains(domain.Reasoning, want) {
			t.Errorf("reasoning must say %q: %s", want, domain.Reasoning)
		}
	}
}

// TestConfiscationImpliesHigh enforces the ABI invariant the contract relies
// on: anything matching ConfiscationMask is at least High.
func TestConfiscationImpliesHigh(t *testing.T) {
	eng := mechanics.NewEngine()
	for _, dir := range []string{
		"aqua-clear-verified", "shx-clear-flagslocked", "usdc-revocable-regulated",
		"berkshire-clawback-scam", "doge-noflags-scam",
	} {
		rep, err := eng.Run(context.Background(), loadSubject(t, dir))
		if err != nil {
			t.Fatal(err)
		}
		if rep.Mechanics&mechanics.ConfiscationMask != 0 && rep.Base < mechanics.High {
			t.Errorf("%s: confiscation-capable but base severity %v < high", dir, rep.Base)
		}
	}
}
