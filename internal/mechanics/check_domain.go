package mechanics

import (
	"context"
	"fmt"

	"github.com/use-assay/assay/internal/sep1"
)

// DomainCheck performs reciprocal SEP-1 domain verification.
//
// It never contributes to severity. Its output is the Accountability field:
// whether an identifiable party has publicly claimed this asset. A verified
// domain does not make an issuer's confiscation power any weaker; it only
// means there is someone to name.
type DomainCheck struct{}

// ID implements Check.
func (DomainCheck) ID() string { return "sep1-domain" }

// Describe implements Check.
func (DomainCheck) Describe() string {
	return "Checks whether the issuer's advertised home_domain publishes a " +
		"stellar.toml that claims this exact asset. Establishes accountability, " +
		"not safety: it never raises or lowers severity."
}

// Run implements Check.
//
// Verification requires both directions to agree. The account advertises a
// home_domain, and that domain's stellar.toml must list this code AND this
// issuer. Either half alone is worthless: home_domain is a free-text field any
// account can set to any string, and a stellar.toml can list any asset code it
// likes. Only the round trip is evidence.
func (c DomainCheck) Run(_ context.Context, s *Subject) (Finding, error) {
	f := Finding{
		Check:    c.ID(),
		Title:    "Issuer domain verification",
		Severity: Clear, // accountability is never severity
		Evidence: []Evidence{},
	}
	acc := AccountabilityUnknown
	f.Accountability = &acc

	domain := s.HomeDomain()
	if domain == "" {
		f.Mechanics = MechDomainUnverified
		f.Reasoning = "The issuer account advertises no home_domain, so there is no " +
			"published identity to verify against. Nobody has publicly claimed this asset."
		return f, nil
	}

	if s.Toml == nil {
		acc = AccountabilityUnverified
		f.Mechanics = MechDomainUnverified
		if s.TomlRefused {
			// A host-policy refusal is a decision Assay made, not a source that
			// failed. It is reported as attributed evidence, the same way a
			// fetch failure is, but labelled Refused so a consumer can tell
			// "Assay declined to fetch this host" from "the host did not
			// answer" without reading the claim text.
			f.Reasoning = fmt.Sprintf(
				"The issuer advertises home_domain %q, which names a host Assay "+
					"refuses to fetch from (%s). Non-public hosts — loopback, private "+
					"and link-local addresses, and the cloud metadata address — are "+
					"refused so an issuer cannot point the scanner at the network the "+
					"scanner runs on. The domain claim is therefore unverified: the "+
					"host was never read.",
				domain, s.TomlErr)
			f.Evidence = append(f.Evidence, Evidence{
				Source:      "stellar.toml",
				URL:         s.TomlURL,
				Claim:       "refused: " + s.TomlErr,
				RetrievedAt: s.TomlAttemptedAt,
				Attempted:   true,
				Refused:     true,
			})
			return f, nil
		}
		f.Reasoning = fmt.Sprintf(
			"The issuer advertises home_domain %q, but its stellar.toml could not be "+
				"read (%s). The domain claim is unverified: anyone can set home_domain "+
				"to any value, so an unreachable toml proves nothing about who issued this.",
			domain, s.TomlErr)
		f.Evidence = append(f.Evidence, Evidence{
			Source: "stellar.toml",
			URL:    s.TomlURL,
			Claim:  "not retrievable: " + s.TomlErr,
			// The toml never answered, so this carries the attempt time, not a
			// retrieval time — and says so programmatically.
			RetrievedAt: s.TomlAttemptedAt,
			Attempted:   true,
		})
		return f, nil
	}

	if !s.Toml.Claims(s.Asset.Code, s.Asset.Issuer) {
		// SEP-0001 lets a currency entry delegate to its own TOML file, in
		// which case the entry carries no code or issuer to match. When those
		// links were followed, a match there is a claim like any other; when
		// they could not all be read, the answer stays unresolved and must not
		// be reported as a refusal. Overstating a negative is the same class of
		// error as overstating a positive.
		if res := s.TomlLinked; res != nil {
			return c.resolveLinked(f, s, domain, res), nil
		}

		// Links exist but were not followed: this is the loader path (fixtures
		// carry no network), so the hedge is preserved verbatim rather than
		// claiming the domain failed to name an asset it may have named in a
		// document Assay never read.
		if linked := s.Toml.LinkedCurrencies(); linked > 0 {
			acc = AccountabilityUnverified
			f.Mechanics = MechDomainUnverified
			f.Reasoning = fmt.Sprintf(
				"The issuer advertises home_domain %q and that domain publishes a "+
					"stellar.toml, but this asset (%s) is not declared inline in its "+
					"CURRENCIES. The toml delegates %d currency entries to separate "+
					"per-currency TOML files, which were not followed here, so this "+
					"asset may be claimed in one of them. Treated as unverified "+
					"because it is unconfirmed, not because it was refuted.",
				domain, s.Asset, linked)
			f.Evidence = append(f.Evidence, Evidence{
				Source: "stellar.toml",
				URL:    s.Toml.URL,
				Claim: fmt.Sprintf(
					"CURRENCIES lists %d entries, none matching %s inline; %d are links not followed",
					len(s.Toml.Currencies), s.Asset, linked),
				RetrievedAt: s.Toml.FetchedAt,
			})
			return f, nil
		}

		acc = AccountabilityUnverified
		f.Mechanics = MechDomainUnverified
		f.Reasoning = fmt.Sprintf(
			"The issuer advertises home_domain %q and that domain publishes a "+
				"stellar.toml, but the toml does not list this asset (%s) in its "+
				"CURRENCIES. The domain has not claimed this asset, so the association "+
				"is asserted by the issuer only and is not reciprocated.",
			domain, s.Asset)
		f.Evidence = append(f.Evidence, Evidence{
			Source: "stellar.toml",
			URL:    s.Toml.URL,
			Claim: fmt.Sprintf("CURRENCIES lists %d entries, none matching %s",
				len(s.Toml.Currencies), s.Asset),
			RetrievedAt: s.Toml.FetchedAt,
		})
		return f, nil
	}

	acc = AccountabilityVerified
	f.Reasoning = fmt.Sprintf(
		"The issuer advertises home_domain %q, and that domain's stellar.toml lists "+
			"this exact code and issuer. The association is reciprocal, so a named "+
			"party has publicly claimed this asset. This says nothing about what the "+
			"issuer can do to your balance — see the capability finding for that.",
		domain)
	f.Evidence = append(f.Evidence, Evidence{
		Source:      "stellar.toml",
		URL:         s.Toml.URL,
		Claim:       "CURRENCIES claims " + s.Asset.String(),
		RetrievedAt: s.Toml.FetchedAt,
	})
	return f, nil
}

// resolveLinked renders the domain finding for an issuer whose asset was not
// declared inline but whose per-currency links were followed.
//
// A match in a linked document is a claim exactly like an inline one, so it
// sets verified accountability. Everything else stays unverified, matching the
// rule this check has always followed — a domain that advertised an asset it
// did not confirm is unverified — but the reasoning distinguishes a genuine
// refusal (every link was read and none named the asset) from an unresolved
// answer (a link could not be read, or the follow bound was reached). Those
// must never render the same: overstating a negative is the same class of
// error as overstating a positive.
func (DomainCheck) resolveLinked(f Finding, s *Subject, domain string, res *sep1.LinkedResolution) Finding {
	if res.Claimed {
		acc := AccountabilityVerified
		f.Accountability = &acc

		retrieved := s.Toml.FetchedAt
		for _, ld := range res.Docs {
			if ld.URL == res.ClaimedURL && ld.Doc != nil {
				retrieved = ld.Doc.FetchedAt
			}
		}
		f.Reasoning = fmt.Sprintf(
			"The issuer advertises home_domain %q, and this asset (%s) is not declared "+
				"inline in that domain's stellar.toml, but a per-currency TOML it links to "+
				"(%s) names this exact code and issuer. The association is reciprocal, so a "+
				"named party has publicly claimed this asset. This says nothing about what "+
				"the issuer can do to your balance — see the capability finding for that.",
			domain, s.Asset, res.ClaimedURL)
		f.Evidence = append(f.Evidence, Evidence{
			Source:      "stellar.toml",
			URL:         res.ClaimedURL,
			Claim:       "linked document claims " + s.Asset.String(),
			RetrievedAt: retrieved,
		})
		return f
	}

	acc := AccountabilityUnverified
	f.Accountability = &acc
	f.Mechanics = MechDomainUnverified

	// The bound was reached before every link could be read. The documents
	// past the bound may have claimed the asset, so this is unresolved, not a
	// refusal, and the report says the bound was hit.
	if res.Deferred > 0 {
		f.Reasoning = fmt.Sprintf(
			"The issuer advertises home_domain %q and that domain publishes a "+
				"stellar.toml, but this asset (%s) is not declared inline in its "+
				"CURRENCIES. The toml delegates %d currency entries to separate "+
				"per-currency TOML files; Assay followed the first %d and left %d "+
				"unfollowed because its bound of %d documents was reached, so this "+
				"asset may be claimed in one of the unread documents. Treated as "+
				"unverified because it is unconfirmed, not because it was refuted.",
			domain, s.Asset, res.Attempted+res.Deferred, res.Attempted, res.Deferred,
			sep1.MaxLinkedDocuments)
		f.Evidence = append(f.Evidence, Evidence{
			Source: "stellar.toml",
			URL:    s.Toml.URL,
			Claim: fmt.Sprintf(
				"CURRENCIES lists %d entries, none matching %s inline; %d linked documents left unread (bound: %d)",
				len(s.Toml.Currencies), s.Asset, res.Deferred, sep1.MaxLinkedDocuments),
			RetrievedAt: s.Toml.FetchedAt,
		})
		return f
	}

	// At least one link could not be read. Whether it claimed the asset is
	// simply unknown, so the answer stays unresolved and the reasoning keeps
	// the hedge — it never claims the domain failed to name this asset.
	unread := 0
	for _, ld := range res.Docs {
		if ld.Err != "" {
			unread++
		}
	}
	if unread > 0 {
		f.Reasoning = fmt.Sprintf(
			"The issuer advertises home_domain %q and that domain publishes a "+
				"stellar.toml, but this asset (%s) is not declared inline in its "+
				"CURRENCIES. The toml delegates %d currency entries to separate "+
				"per-currency TOML files; %d of them could not be read, so this "+
				"asset may be claimed in one of them. Treated as unverified because "+
				"it is unconfirmed, not because it was refuted.",
			domain, s.Asset, res.Attempted, unread)
		// The main toml did resolve; it is some of its links that did not. The
		// claim is about the document Assay did read, so it carries that
		// document's retrieval time and is not marked Attempted.
		f.Evidence = append(f.Evidence, Evidence{
			Source: "stellar.toml",
			URL:    s.Toml.URL,
			Claim: fmt.Sprintf(
				"CURRENCIES lists %d entries, none matching %s inline; %d of %d linked documents could not be read",
				len(s.Toml.Currencies), s.Asset, unread, res.Attempted),
			RetrievedAt: s.Toml.FetchedAt,
		})
		return f
	}

	// Every link was read and none names the asset. This is a genuine
	// refusal: the domain published a stellar.toml and its linked documents,
	// and none of them claims this code and issuer.
	f.Reasoning = fmt.Sprintf(
		"The issuer advertises home_domain %q and that domain publishes a "+
			"stellar.toml, but neither the toml's CURRENCIES nor the %d per-currency "+
			"documents it links to list this asset (%s). The domain has not claimed "+
			"this asset, so the association is asserted by the issuer only and is not "+
			"reciprocated.",
		domain, res.Attempted, s.Asset)
	f.Evidence = append(f.Evidence, Evidence{
		Source: "stellar.toml",
		URL:    s.Toml.URL,
		Claim: fmt.Sprintf(
			"CURRENCIES lists %d entries and %d linked documents, none matching %s",
			len(s.Toml.Currencies), res.Attempted, s.Asset),
		RetrievedAt: s.Toml.FetchedAt,
	})
	return f
}
