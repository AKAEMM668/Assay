package mechanics

import (
	"context"
	"fmt"
	"strings"
)

// ReputationCheck folds in StellarExpert's curated reputation data.
//
// Assay does not maintain a scam list, a rating, or a domain blocklist. Those
// exist, they are actively curated, and this check consumes them. Everything it
// produces is attributed Evidence naming StellarExpert and the URL the claim
// came from.
//
// It is the only check permitted to escalate, and it can only ever raise the
// level. A confirmed malicious listing is decisive evidence of abuse. Absence
// from the list is not evidence of anything: most legitimate assets are absent,
// and so is every scam that has not been reported yet.
type ReputationCheck struct{}

// ID implements Check.
func (ReputationCheck) ID() string { return "reputation" }

// Describe implements Check.
func (ReputationCheck) Describe() string {
	return "Consumes StellarExpert's curated address directory and " +
		"malicious-domain blocklist as attributed evidence. Escalates to " +
		"critical on a confirmed listing; never lowers severity."
}

// Run implements Check.
func (c ReputationCheck) Run(_ context.Context, s *Subject) (Finding, error) {
	f := Finding{
		Check:      c.ID(),
		Title:      "Curated reputation signals",
		Severity:   Clear,
		Escalation: true,
		Evidence:   []Evidence{},
	}

	var flagged []string
	// unreachable names sources that were asked and did not answer. It is kept
	// separate from "answered, not listed" because collapsing the two is
	// exactly how a scanner reports an outage as a clean bill of health.
	var unreachable []string

	if s.DirectoryErr != "" {
		unreachable = append(unreachable, "the curated directory")
		f.Evidence = append(f.Evidence, Evidence{
			Source: "stellar.expert/directory",
			URL:    s.DirectoryURL,
			Claim:  "not retrievable: " + s.DirectoryErr,
			// The source never answered, so this is the attempt time — marked
			// as such, because an attempt is not an answer.
			RetrievedAt: s.DirectoryAttemptedAt,
			Attempted:   true,
		})
	}

	if s.BlockedErr != "" {
		unreachable = append(unreachable, "the malicious-domain blocklist")
		f.Evidence = append(f.Evidence, Evidence{
			Source:      "stellar.expert/blocked-domains",
			URL:         s.BlockedURL,
			Claim:       "not retrievable: " + s.BlockedErr,
			RetrievedAt: s.BlockedAttemptedAt,
			Attempted:   true,
		})
	}

	if s.Directory != nil {
		tags := strings.Join(s.Directory.Tags, ", ")
		f.Evidence = append(f.Evidence, Evidence{
			Source: "stellar.expert/directory",
			URL:    s.DirectoryURL,
			Claim: fmt.Sprintf("listed as %q (domain %q, tags: %s)",
				s.Directory.Name, s.Directory.Domain, tags),
			RetrievedAt: s.DirectoryFetchedAt,
		})
		for _, tag := range []string{"malicious", "unsafe"} {
			if s.Directory.HasTag(tag) {
				flagged = append(flagged, fmt.Sprintf("the curated directory tags the issuer %q", tag))
				break
			}
		}
	}

	if s.Blocked != nil {
		f.Evidence = append(f.Evidence, Evidence{
			Source:      "stellar.expert/blocked-domains",
			URL:         s.BlockedURL,
			Claim:       fmt.Sprintf("domain %q blocked=%t", s.Blocked.Domain, s.Blocked.Blocked),
			RetrievedAt: s.BlockedFetchedAt,
		})
		if s.Blocked.Blocked {
			flagged = append(flagged, fmt.Sprintf(
				"the malicious-domain blocklist contains %q", s.Blocked.Domain))
		}
	}

	// A positive listing decides the question even if the other source is down.
	// Evidence of abuse does not become less true because a second endpoint
	// timed out, and Critical is the ceiling, so nothing that is still missing
	// could raise the level further.
	if len(flagged) > 0 {
		f.Severity = Critical
		f.Mechanics = MechBlocklisted
		f.Reasoning = "Escalated to critical because " + joinPowers(flagged) +
			". This is StellarExpert's determination, reported here as their claim " +
			"and not re-derived by Assay. It raises the level regardless of what the " +
			"issuer's flags allow."
		return f, nil
	}

	// Nothing was flagged — but that only means something if every source
	// actually answered. Reporting an outage as a clean result is the one
	// failure this check must never have, because reputation is the only axis
	// that can escalate: an asset that is critical solely by escalation reads
	// as its bare capability severity when this source is unavailable.
	if len(unreachable) > 0 {
		f.Undetermined = true
		f.Reasoning = "Reputation could not be determined: " + joinPowers(unreachable) +
			" did not answer, and the failure is recorded above verbatim. This is " +
			"not a clean result. Absence of a malicious listing is only meaningful " +
			"when the list was actually read, and an asset whose only adverse signal " +
			"is a curated listing would look clear here. Treat the severity below as " +
			"a floor rather than an answer."
		return f, nil
	}

	if len(f.Evidence) == 0 {
		f.Reasoning = "Curated sources were reachable and returned nothing for this " +
			"issuer. That is the normal case and is not a positive signal: absence " +
			"from a scam list is not evidence of safety."
		return f, nil
	}

	f.Reasoning = "Curated sources returned data for this issuer and none of it " +
		"flags the issuer as malicious. Recorded as attributed evidence only: it " +
		"does not lower the capability severity, because a named issuer holds the " +
		"same power over your balance as an anonymous one."
	return f, nil
}
