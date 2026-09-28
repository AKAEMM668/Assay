// Package mechanics classifies trap risk for a Stellar asset from the
// ledger's own rules.
//
// The design rule here is that checks perform no I/O. Everything a check needs
// is fetched once, up front, into a Subject; a check is then a pure function
// from Subject to Finding. That keeps checks deterministic, makes them testable
// from fixtures with no network, and confines every fetcher to its own package
// where it can be extracted later.
package mechanics

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/use-assay/assay/internal/horizon"
	"github.com/use-assay/assay/internal/sep1"
	"github.com/use-assay/assay/internal/stellarexpert"
)

// Asset identifies a classic Stellar asset.
type Asset struct {
	Code   string `json:"code"`
	Issuer string `json:"issuer"`
}

// String renders the canonical CODE-ISSUER form.
func (a Asset) String() string { return a.Code + "-" + a.Issuer }

// Evidence is a single attributed claim from a named source.
//
// Every consumed signal enters the report through this type. Attribution is
// structural rather than conventional: because a check can only surface an
// outside claim by constructing an Evidence with its source and URL, there is
// no code path that renders someone else's data as an Assay conclusion.
type Evidence struct {
	Source      string    `json:"source"`
	URL         string    `json:"url"`
	Claim       string    `json:"claim"`
	RetrievedAt time.Time `json:"retrieved_at"`
	// Attempted marks evidence whose RetrievedAt is the time the fetch was
	// ATTEMPTED, not the time the source answered: the fetch failed, so there
	// is no completion time to record. The Claim of such evidence always reads
	// "not retrievable: <reason>", but a consumer must not have to parse
	// English to distinguish "this source said so at T" from "we asked at T
	// and got nothing" — the same programmatic distinguishability rule the
	// Undetermined flag follows for findings.
	Attempted bool `json:"attempted"`
}

// Finding is one check's result.
type Finding struct {
	Check    string   `json:"check"`
	Title    string   `json:"title"`
	Severity Severity `json:"severity"`
	// Escalation marks a finding whose severity comes from reputation rather
	// than from issuer capability. The engine keeps these separate so that the
	// capability-only base severity stays auditable.
	Escalation bool `json:"escalation"`
	// Undetermined marks a check that could not reach a conclusion because a
	// source it depends on was unreachable. It is not the same as a check that
	// looked and found nothing, and the two must stay distinguishable by a
	// program, not only by a human reading Reasoning.
	//
	// A check sets this only for the part of its answer that is missing. A
	// positive signal that did arrive is still valid: reputation that reaches
	// a source and finds a malicious listing escalates normally, because
	// evidence of abuse does not become less true when a second source is
	// down.
	Undetermined bool `json:"undetermined"`
	// UndeterminedBySource records which source caused this finding to be
	// undetermined. This distinguishes a source failing (e.g. StellarExpert
	// unreachable) from a source being skipped (e.g. home_domain empty).
	UndeterminedBySource map[string]int `json:"undetermined_by_source,omitempty"`
	// UndeterminedRate is the rate for this specific finding, expressed as
	// "numerator/denominator" where denominator is the total number of checks
	// run. When the sample is small (fewer than 20 scans), the rate is reported
	// with its sample size noted, never as a general claim.
	UndeterminedRate string `json:"undetermined_rate,omitempty"`
	// Reasoning always states the raw capability in plain language, whatever
	// the severity works out to.
	Reasoning string `json:"reasoning"`
	// Mechanics are the bits this check observed.
	Mechanics Mechanic `json:"-"`
	// MechanicNames is the human-readable form of Mechanics.
	MechanicNames []string `json:"mechanics"`
	// Accountability is set only by the check that establishes it.
	Accountability *Accountability `json:"accountability,omitempty"`
	Evidence       []Evidence      `json:"evidence"`
}

// Subject is the pre-fetched state a check reasons over. Checks must not reach
// outside it.
//
// Every fetch records its own completion time, and every failed fetch records
// its attempt time. Evidence.RetrievedAt must therefore come from the field
// matching the source the evidence attributes — a claim is only as fresh as
// the source that actually made it, and a StellarExpert answer that arrived
// twenty seconds after the Horizon one must not report Horizon's instant.
type Subject struct {
	Asset Asset
	Stat  *horizon.AssetStat
	// StatFetchedAt is when Horizon answered the /assets lookup.
	StatFetchedAt time.Time
	Issuer        *horizon.Account
	// IssuerFetchedAt is when Horizon answered the issuer /accounts lookup.
	IssuerFetchedAt time.Time

	// Toml is the issuer's stellar.toml if it resolved. TomlErr records why it
	// did not, and is reported verbatim rather than being smoothed over.
	// A resolved Doc carries its own FetchedAt; TomlAttemptedAt is when the
	// fetch was attempted, used for failure evidence where no Doc exists.
	Toml            *sep1.Doc
	TomlURL         string
	TomlErr         string
	TomlAttemptedAt time.Time

	// Directory and Blocked are the curated reputation signals. Each has an Err
	// field for the same reason TomlErr exists: a nil entry means "not listed"
	// only when the source actually answered. A nil entry with a non-empty Err
	// means the source was never reached, which is a different fact and must
	// not be allowed to render as the same one.
	//
	// The FetchedAt fields are when the source answered; the AttemptedAt fields
	// are when it was asked and did not. AttemptedAt is always set (the attempt
	// happened whether or not it succeeded), so failure evidence always has a
	// time to carry.
	Directory            *stellarexpert.DirectoryEntry
	DirectoryURL         string
	DirectoryErr         string
	DirectoryFetchedAt   time.Time
	DirectoryAttemptedAt time.Time
	Blocked              *stellarexpert.BlockedDomain
	BlockedURL           string
	BlockedErr           string
	BlockedFetchedAt     time.Time
	BlockedAttemptedAt   time.Time

	// Holder is the account ID of a specific holder when per-trustline analysis
	// was requested. Empty when no holder was specified; the trustline check is
	// not run in that case and behavior is identical to a no-holder scan.
	Holder string
	// HolderTrustline is the holder's balance entry for this asset. Populated
	// when Holder is non-empty and the holder holds the asset.
	// HolderTrustlineErr records why it was not available.
	HolderTrustline    *horizon.TrustlineBalance
	HolderTrustlineErr string
	// HolderFetchedAt is when Horizon answered the holder /accounts lookup;
	// HolderAttemptedAt is when it was asked. The same success/failure split
	// as above: an absent trustline (a nil entry with no error) still has a
	// completion time — the source did answer, "not listed".
	HolderFetchedAt   time.Time
	HolderAttemptedAt time.Time

	// ScannedAt is when the scan started. It is the report-level timestamp:
	// evidence carries the time of the source it came from, and the report
	// carries the time the subject assembly began.
	ScannedAt time.Time
	FetchedAt time.Time
}

// HomeDomain returns the issuer's advertised home_domain, if any.
func (s *Subject) HomeDomain() string {
	if s.Issuer == nil {
		return ""
	}
	return s.Issuer.HomeDomain
}

// Check is a single mechanic classifier. Implementations are pure functions
// over the Subject and must not perform I/O.
type Check interface {
	// ID is the stable identifier used in reports and issue tracking.
	ID() string
	// Describe states what the check concludes, and what it does not.
	Describe() string
	// Run classifies the subject.
	Run(ctx context.Context, s *Subject) (Finding, error)
}

// Report is the aggregated result of running every check over one asset.
type Report struct {
	Asset Asset `json:"asset"`

	// Severity is the final level: the capability base, raised by any
	// reputation escalation.
	Severity Severity `json:"severity"`
	// Base is the capability-only severity before escalation. Base and
	// Severity differ only when a curated source flagged this issuer, which
	// makes every escalation visible and auditable.
	Base Severity `json:"base_severity"`
	// Escalated reports whether reputation raised the level.
	Escalated bool `json:"escalated"`

	// Accountability is reported alongside severity, never folded into it.
	Accountability Accountability `json:"accountability"`

	// State is the overall verdict state of the report:
	//   - "valid": a fresh, complete verdict.
	//   - "unknown": a check could not conclude (undetermined or unevaluated).
	//   - "stale": the verdict was complete when made, but is older than the
	//     freshness policy window.
	State State `json:"state"`

	// Stale reports whether this verdict is older than the policy window.
	// Kept distinct from Undetermined: a stale report was complete when made,
	// whereas an undetermined report was never complete.
	Stale bool `json:"stale"`

	// StaleReason explains why the report is considered stale, if set.
	StaleReason string `json:"stale_reason,omitempty"`

	// Undetermined reports that at least one check could not complete because
	// a source it depends on was unreachable, so this report is a partial answer.
	//
	// Severity is still whatever the checks that did complete established, and
	// it is never inflated to compensate — inventing a level would be its own
	// dishonesty. What this says is that the level may be too low, and that
	// nobody should read the absence of an escalation as evidence there is
	// nothing to escalate on.
	Undetermined bool `json:"undetermined"`
	// UndeterminedChecks names the checks that could not complete, so a
	// consumer can see which axis is missing rather than only that one is.
	UndeterminedChecks []string `json:"undetermined_checks"`
	// UndeterminedBySource reports, for each source, how many checks could not
	// complete because that source was unreachable. The keys are source names
	// such as "horizon", "stellar.expert/directory", and "stellar.expert/blocked-domains".
	// This distinguishes a source failing (unreachable) from a source being skipped
	// (e.g. home_domain empty, not attempted).
	UndeterminedBySource map[string]int `json:"undetermined_by_source,omitempty"`
	// UndeterminedRate is the undetermined rate for this report, expressed as
	// "numerator/denominator" where denominator is the total number of checks
	// run for this asset. When the sample is small (fewer than 20 scans), the
	// rate is reported with its sample size noted, never as a general claim.
	UndeterminedRate string `json:"undetermined_rate,omitempty"`

	// CheckSet is the sorted IDs of the checks the engine that produced this
	// report actually ran. It is what makes a suppressed check — one removed
	// from the engine — distinguishable from a check that ran and found
	// nothing: without it, a report from a smaller engine is byte-identical to
	// one from the full engine whenever the removed check moved no other
	// field, and the resulting attestation hashes the same.
	//
	// It is committed to by evidence_hash under the v2 preimage encoding (see
	// internal/attest), so a verifier can name the check a report is missing
	// rather than report a generic mismatch. Reports written before
	// check-set binding carry no CheckSet and are read as "unknown", never as
	// "complete".
	CheckSet []string `json:"checks,omitempty"`

	Mechanics     Mechanic   `json:"-"`
	MechanicNames []string   `json:"mechanics"`
	Findings      []Finding  `json:"findings"`
	Evidence      []Evidence `json:"evidence"`
	ScannedAt     time.Time  `json:"scanned_at"`

	// ObservationWindowStart is the start of the observation window for this report.
	ObservationWindowStart time.Time `json:"observation_window_start,omitempty"`
	// ObservationWindowEnd is the end of the observation window for this report.
	ObservationWindowEnd time.Time `json:"observation_window_end,omitempty"`
}

// Engine runs a set of checks over a Subject.
type Engine struct {
	Checks []Check
}

// NewEngine returns an Engine with the default check set.
func NewEngine() *Engine {
	return &Engine{Checks: []Check{
		CapabilityCheck{},
		MutabilityCheck{},
		DomainCheck{},
		ReputationCheck{},
	}}
}

// CheckIDs returns the stable IDs of the checks this engine runs, sorted so
// the set is comparable and hash-stable regardless of registration order.
//
// The engine's check set is part of what a report claims: a report says "these
// checks ran" as well as "here is what they found". Returning the set lets a
// verifier detect a check that was removed rather than one that found nothing.
func (e *Engine) CheckIDs() []string {
	ids := make([]string, 0, len(e.Checks))
	for _, c := range e.Checks {
		ids = append(ids, c.ID())
	}
	sort.Strings(ids)
	return ids
}

// Run executes every check and aggregates the results.
//
// Aggregation rules, which are the judgment model in code:
//
//   - Base severity is the maximum over non-escalation findings. That is pure
//     capability.
//   - Final severity is the maximum over all findings, so reputation can only
//     ever raise the level.
//   - Accountability is taken from whichever check establishes it and is not
//     permitted to influence either severity.
//
// Undetermined tracking:
//   - UndeterminedBySource records, for each source, how many checks could not
//     complete because that source was unreachable. This distinguishes a source
//     failing (e.g. StellarExpert unreachable) from a source being skipped
//     (e.g. home_domain empty, not attempted).
//   - UndeterminedRate is the undetermined rate expressed as "numerator/denominator"
//     where denominator is the total number of checks run for this asset.
//     When the sample is small (fewer than 20 scans), the rate is reported with
//     its sample size noted, never as a general claim.
//   - ObservationWindowStart/End records the start and end of the observation
//     window for the scan.
func (e *Engine) Run(ctx context.Context, s *Subject) (*Report, error) {
	scannedAt := s.ScannedAt
	if scannedAt.IsZero() && !s.FetchedAt.IsZero() {
		scannedAt = s.FetchedAt
	}
	rep := &Report{
		Asset:              s.Asset,
		Accountability:     AccountabilityUnknown,
		ScannedAt:          scannedAt,
		CheckSet:           e.CheckIDs(),
		Findings:           []Finding{},
		Evidence:           []Evidence{},
		UndeterminedChecks: []string{},
	}

	totalChecks := len(e.Checks)
	undeterminedCount := 0

	for _, c := range e.Checks {
		f, err := c.Run(ctx, s)
		if err != nil {
			return nil, fmt.Errorf("check %s: %w", c.ID(), err)
		}
		f.MechanicNames = f.Mechanics.Names()

		if f.Escalation {
			if f.Severity > rep.Severity {
				rep.Severity = f.Severity
			}
		} else if f.Severity > rep.Base {
			rep.Base = f.Severity
		}

		// A degraded check is recorded, never averaged away. One unreachable
		// source is enough to make the whole report partial, because a caller
		// cannot know which axis mattered for the asset in front of them.
		if f.Undetermined {
			rep.Undetermined = true
			rep.UndeterminedChecks = append(rep.UndeterminedChecks, f.Check)
			undeterminedCount++

			// Determine the source that caused the undetermined status.
			// Priority: 1) evidence source, 2) reasoning keywords, 3) subject fields.
			source := determineUndeterminedSource(f, s)
			rep.UndeterminedBySource[source]++
		}

		if f.Accountability != nil {
			rep.Accountability = *f.Accountability
		}
		// The escalation invariant, enforced here rather than left as
		// convention: a finding marked Escalation may raise the level and set
		// non-capability bits (blocklisted), but must never set a capability
		// bit. The on-chain gate masks CapabilityMask out of this bitset and
		// trusts what it sees; an escalation finding carrying a capability bit
		// would make the report assert a power the issuer does not hold on the
		// ledger. Fail loudly instead of masking the bits away — silently
		// dropping them would hide exactly the bug this guard exists to catch.
		if f.Escalation && f.Mechanics&CapabilityMask != 0 {
			return nil, fmt.Errorf(
				"check %s: escalation finding sets capability bits %v; "+
					"escalation must never grant a capability the issuer does not hold",
				c.ID(), (f.Mechanics & CapabilityMask).Names())
		}
		rep.Mechanics |= f.Mechanics
		rep.Findings = append(rep.Findings, f)
		rep.Evidence = append(rep.Evidence, f.Evidence...)
	}

	// Calculate undetermined rate as "numerator/denominator".
	// denominator = total number of checks run (len(e.Checks)).
	// numerator = number of checks that were undetermined.
	if undeterminedCount > 0 && totalChecks > 0 {
		rep.UndeterminedRate = fmt.Sprintf("%d/%d", undeterminedCount, totalChecks)
	}

	// Set observation window: start from the scan start time, end at scanned at.
	rep.ObservationWindowStart = s.ScannedAt
	rep.ObservationWindowEnd = s.ScannedAt

	if rep.Base > rep.Severity {
		rep.Severity = rep.Base
	}
	rep.Escalated = rep.Severity > rep.Base
	rep.MechanicNames = rep.Mechanics.Names()

	if rep.Undetermined || rep.Base == Unevaluated || rep.Severity == Unevaluated {
		rep.State = StateUnknown
	} else {
		rep.State = StateValid
	}

	sort.SliceStable(rep.Findings, func(i, j int) bool {
		return rep.Findings[i].Severity > rep.Findings[j].Severity
	})
	return rep, nil
}

// determineUndeterminedSource figures out which source caused a check to be
// undetermined. It prioritizes: 1) the finding's evidence source, 2) keywords
// in the reasoning, 3) subject-level failure fields.
func determineUndeterminedSource(f Finding, s *Subject) string {
	// 1) Check the finding's evidence for a source attribution.
	if len(f.Evidence) > 0 {
		for _, e := range f.Evidence {
			if e.Source != "" {
				return e.Source
			}
		}
	}

	// 2) Check reasoning keywords for source hints.
	low := strings.ToLower(f.Reasoning)
	if strings.Contains(low, "horizon") || strings.Contains(low, "asset not found") {
		return "horizon"
	}
	if strings.Contains(low, "stellar.expert/directory") || strings.Contains(low, "curated directory") {
		return "stellar.expert/directory"
	}
	if strings.Contains(low, "stellar.expert/blocked") || strings.Contains(low, "blocked-domains") {
		return "stellar.expert/blocked-domains"
	}
	if strings.Contains(low, "home_domain") || strings.Contains(low, "stellar.toml") {
		return "stellar.toml"
	}
	if strings.Contains(low, "trustline") {
		return "horizon/trustline"
	}

	// 3) Fall back to subject-level failure fields.
	if s.Stat == nil {
		return "horizon"
	}
	if s.DirectoryErr != "" {
		return "stellar.expert/directory"
	}
	if s.BlockedErr != "" {
		return "stellar.expert/blocked-domains"
	}
	if s.TomlErr != "" {
		return "stellar.toml"
	}
	if s.HolderTrustlineErr != "" || s.HolderTrustline == nil {
		return "horizon/trustline"
	}

	// 4) Last resort: generic label.
	return "unknown"
}
