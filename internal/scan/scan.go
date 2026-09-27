// Package scan assembles a mechanics.Subject from live sources and runs the
// engine over it.
//
// This is the only place in Assay that performs network I/O for a scan. It
// exists so that the checks never do: every fetch happens here, once, and the
// result is handed to pure classifiers. That split is what makes the checks
// testable without a network and keeps each fetcher independently extractable.
package scan

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/use-assay/assay/internal/horizon"
	"github.com/use-assay/assay/internal/mechanics"
	"github.com/use-assay/assay/internal/sep1"
	"github.com/use-assay/assay/internal/stellarexpert"
)

// issuerRE matches a Stellar ed25519 public key.
var issuerRE = regexp.MustCompile(`^G[A-Z2-7]{55}$`)

// codeRE matches a valid classic asset code (1-12 alphanumeric).
var codeRE = regexp.MustCompile(`^[A-Za-z0-9]{1,12}$`)

// ErrBadAsset reports an unparseable asset identifier.
var ErrBadAsset = errors.New("scan: invalid asset")

// ErrBadHolder reports an invalid holder account ID.
var ErrBadHolder = errors.New("scan: invalid holder account ID")

// ValidateHolder checks that id is a valid Stellar ed25519 public key suitable
// for use as a holder account ID.
func ValidateHolder(id string) error {
	if !issuerRE.MatchString(id) {
		return fmt.Errorf("%w: %q", ErrBadHolder, id)
	}
	return nil
}

// ParseAsset accepts the canonical CODE-ISSUER form and validates both halves.
func ParseAsset(s string) (mechanics.Asset, error) {
	s = strings.TrimSpace(s)
	code, issuer, ok := strings.Cut(s, "-")
	if !ok {
		return mechanics.Asset{}, fmt.Errorf("%w: expected CODE-ISSUER, got %q", ErrBadAsset, s)
	}
	// Trailing "-1"/"-2" suffixes appear in some explorer asset identifiers.
	if i := strings.Index(issuer, "-"); i >= 0 {
		issuer = issuer[:i]
	}
	if !codeRE.MatchString(code) {
		return mechanics.Asset{}, fmt.Errorf("%w: bad asset code %q", ErrBadAsset, code)
	}
	if !issuerRE.MatchString(issuer) {
		return mechanics.Asset{}, fmt.Errorf("%w: bad issuer %q", ErrBadAsset, issuer)
	}
	return mechanics.Asset{Code: code, Issuer: issuer}, nil
}

// Scanner fetches subject state and classifies it.
type Scanner struct {
	Horizon *horizon.Client
	Toml    *sep1.Fetcher
	Expert  *stellarexpert.Client
	Engine  *mechanics.Engine
}

// Options configures a Scanner.
//
// The cache options exist because every scan consumes a free, third-party
// service, and the cost of not re-reading it is staleness. Which way to trade
// is a deployment's to make, not a constant's: a one-shot CLI scan can afford
// to re-fetch everything, while a long-lived server answering repeated scans of
// the same issuer should not rebuild them from scratch each time. The default
// is the conservative one documented in docs/caching.md.
//
// Ledger lookups are deliberately NOT covered here. See NewWithOptions.
type Options struct {
	// ReputationDirectoryTTL and ReputationBlocklistTTL bound how long a
	// curated StellarExpert answer may be reused, measured from the fetch that
	// produced it. A zero TTL disables caching of that source.
	ReputationDirectoryTTL time.Duration
	ReputationBlocklistTTL time.Duration

	// NoReputationCache disables the reputation cache outright: every scan
	// re-fetches both curated sources. Use it when a stale answer would be
	// unacceptable and the extra requests are affordable.
	NoReputationCache bool
}

// DefaultOptions returns the production cache policy.
func DefaultOptions() Options {
	return Options{
		ReputationDirectoryTTL: stellarexpert.DefaultDirectoryTTL,
		ReputationBlocklistTTL: stellarexpert.DefaultBlocklistTTL,
	}
}

// New returns a Scanner wired to the public production sources with the
// default cache policy.
func New() *Scanner {
	return NewWithOptions(DefaultOptions())
}

// NewWithOptions returns a Scanner wired to the public production sources with
// the given cache policy.
//
// Only the reputation lookups are cached. Horizon is left uncached on purpose:
// issuer authorization flags are the capability axis severity is derived from,
// they can change in one ledger close (~5 s), and there is no retrieved-at
// field in an attestation that could carry the age of a stale flag read. A TTL
// short enough to be honest about the ledger would not save a request; a TTL
// long enough to save one would misstate the issuer's power. See
// docs/caching.md.
func NewWithOptions(opts Options) *Scanner {
	return &Scanner{
		Horizon: horizon.New(""),
		Toml:    sep1.NewFetcher(),
		Expert:  stellarexpert.NewWithOptions("", expertOptions(opts)),
		Engine:  mechanics.NewEngine(),
	}
}

// expertOptions maps a Scanner's cache policy onto the StellarExpert client's.
func expertOptions(opts Options) stellarexpert.Options {
	o := stellarexpert.DefaultOptions()
	o.DirectoryTTL = opts.ReputationDirectoryTTL
	o.BlocklistTTL = opts.ReputationBlocklistTTL
	if opts.NoReputationCache {
		o.DirectoryTTL = 0
		o.BlocklistTTL = 0
	}
	return o
}

// Subject fetches everything the checks need for one asset.
//
// Only the ledger lookups are fatal: without issuer flags there is no
// classification to make. Every consumed signal is best-effort, because a
// third-party outage must not be able to turn a dangerous asset into an error
// page. When a source is unreachable the failure is recorded verbatim and
// surfaced, never smoothed into a false negative.
func (s *Scanner) Subject(ctx context.Context, a mechanics.Asset) (*mechanics.Subject, error) {
	sub := &mechanics.Subject{Asset: a, ScannedAt: time.Now().UTC()}

	stat, err := s.Horizon.Asset(ctx, a.Code, a.Issuer)
	if err != nil {
		return nil, err
	}
	sub.Stat = stat
	// Each fetch stamps its own completion time. Later temporal statements —
	// how stale one source's answer was relative to another's — are only
	// honest if the times were recorded per source, not reused from the scan
	// start.
	sub.StatFetchedAt = time.Now().UTC()

	issuer, err := s.Horizon.Account(ctx, a.Issuer)
	if err != nil {
		return nil, err
	}
	sub.Issuer = issuer
	sub.IssuerFetchedAt = time.Now().UTC()

	if domain := issuer.HomeDomain; domain != "" {
		sub.TomlURL = sep1.URLFor(domain)
		attempted := time.Now().UTC()
		doc, err := s.Toml.Fetch(ctx, domain)
		if err != nil {
			sub.TomlErr = err.Error()
			// A failed fetch has no completion time, so the attempt time is
			// what failure evidence carries — explicitly labelled as an attempt
			// by Evidence.Attempted.
			sub.TomlAttemptedAt = attempted
		} else {
			sub.Toml = doc
		}

		sub.BlockedURL = s.Expert.BlockedDomainURL(domain)
		attempted = time.Now().UTC()
		blocked, err := s.Expert.BlockedDomain(ctx, domain)
		sub.BlockedAttemptedAt = attempted
		if err != nil {
			sub.BlockedErr = err.Error()
		} else {
			sub.Blocked = blocked.Value
			// The source's OWN completion time, which on a cache hit is the
			// instant the answer was originally fetched. Stamping the lookup
			// time here instead is the one thing the cache must never cause:
			// Evidence.RetrievedAt would then claim a freshness the data does
			// not have, in the report and in the preimage a verifier re-derives.
			sub.BlockedFetchedAt = blocked.FetchedAt
		}
	}

	sub.DirectoryURL = s.Expert.DirectoryURL(a.Issuer)
	attempted := time.Now().UTC()
	entry, err := s.Expert.Directory(ctx, a.Issuer)
	sub.DirectoryAttemptedAt = attempted
	if err != nil {
		sub.DirectoryErr = err.Error()
	} else {
		sub.Directory = entry.Value
		// As above: the directory answer's own fetch time, not this scan's.
		sub.DirectoryFetchedAt = entry.FetchedAt
	}

	return sub, nil
}

// Scan fetches and classifies an asset.
func (s *Scanner) Scan(ctx context.Context, a mechanics.Asset) (*mechanics.Report, error) {
	sub, err := s.Subject(ctx, a)
	if err != nil {
		return nil, err
	}
	return s.Engine.Run(ctx, sub)
}

// SubjectWithHolder fetches everything Subject does, then additionally fetches
// the trustline state for holder if non-empty. When holder is empty the result
// is identical to calling Subject.
func (s *Scanner) SubjectWithHolder(ctx context.Context, a mechanics.Asset, holder string) (*mechanics.Subject, error) {
	sub, err := s.Subject(ctx, a)
	if err != nil {
		return nil, err
	}
	if holder == "" {
		return sub, nil
	}
	sub.Holder = holder
	tl, err := s.Horizon.Trustline(ctx, holder, a.Code, a.Issuer)
	if errors.Is(err, horizon.ErrNotFound) {
		// Holder does not hold the asset; HolderTrustline stays nil with no
		// error. The source did answer — "not listed" — so this records a
		// completion time, not an attempt time.
		sub.HolderFetchedAt = time.Now().UTC()
	} else if err != nil {
		sub.HolderTrustlineErr = err.Error()
		sub.HolderAttemptedAt = time.Now().UTC()
	} else {
		sub.HolderTrustline = tl
		sub.HolderFetchedAt = time.Now().UTC()
	}
	return sub, nil
}

// ScanWithHolder fetches and classifies an asset, optionally adding per-holder
// trustline analysis when holder is non-empty. When holder is empty the result
// is byte-identical to Scan.
func (s *Scanner) ScanWithHolder(ctx context.Context, a mechanics.Asset, holder string) (*mechanics.Report, error) {
	sub, err := s.SubjectWithHolder(ctx, a, holder)
	if err != nil {
		return nil, err
	}
	eng := s.Engine
	if holder != "" {
		eng = &mechanics.Engine{Checks: append([]mechanics.Check{}, s.Engine.Checks...)}
		eng.Checks = append(eng.Checks, mechanics.TrustlineCheck{})
	}
	return eng.Run(ctx, sub)
}
