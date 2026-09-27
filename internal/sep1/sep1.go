// Package sep1 fetches and parses an issuer's stellar.toml (SEP-0001).
//
// Assay uses this for one purpose: reciprocal domain verification. An issuer
// account advertises a home_domain; SEP-1 says that domain publishes a
// stellar.toml at /.well-known/stellar.toml. The link is only meaningful in
// both directions — the account points at the domain, and the domain's
// CURRENCIES list points back at the asset. Either half alone proves nothing,
// because anyone can set home_domain to any string.
//
// This is an extraction candidate for a shared ledger-access library.
package sep1

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/BurntSushi/toml"
)

// version is kept here so every outbound client reports the same tool
// version in its User-Agent. Bump it alongside any scanner-version release;
// the API documents the value in release notes.
const version = "v0.1.0"

// MaxBody caps the stellar.toml read. Real files are a few KB; this stops a
// hostile domain from streaming an unbounded body at the scanner. It is
// exported so the resource-exhaustion tests can assert that a reader is never
// asked for more than this, rather than assuming it.
const MaxBody = 1 << 20 // 1 MiB

// MaxRedirects bounds how many redirects the fetcher will follow before
// giving up. It is set explicitly rather than inherited from net/http's default
// of 10, because the number is part of the security argument: a redirect chain
// is attacker-controlled, and an unbounded one lets a hostile home_domain keep
// the scanner chasing hops (or keep rewriting the final URL the claim is
// attributed to). Five is enough for the ordinary cases — an http-to-https
// upgrade, a trailing-slash or path-normalization hop, an apex-to-www move —
// and small enough to read in one place.
const MaxRedirects = 5

// ErrNoDomain reports that the issuer account advertises no home_domain, so
// there is nothing to verify against.
var ErrNoDomain = errors.New("sep1: issuer has no home_domain")

// Currency is one [[CURRENCIES]] entry.
type Currency struct {
	Code   string `toml:"code"`
	Issuer string `toml:"issuer"`
	Name   string `toml:"name"`
	Status string `toml:"status"`
	// Toml is set when the entry is a link to another stellar.toml rather than
	// an inline declaration.
	Toml string `toml:"toml"`
}

// Doc is the subset of stellar.toml that Assay reads.
type Doc struct {
	Currencies []Currency `toml:"CURRENCIES"`
	// URL is the location the document was actually fetched from, after
	// redirects. It can differ from the requested URL.
	URL string `toml:"-"`
	// FetchedAt records when this document was retrieved.
	FetchedAt time.Time `toml:"-"`
}

// Claims reports whether the document declares the given asset, matching on
// both code and issuer. Matching on code alone would let any domain claim any
// asset code, which is the exact failure this check exists to prevent.
func (d *Doc) Claims(code, issuer string) bool {
	if d == nil {
		return false
	}
	for _, c := range d.Currencies {
		if strings.EqualFold(c.Code, code) && strings.EqualFold(c.Issuer, issuer) {
			return true
		}
	}
	return false
}

// LinkedCurrencies counts entries that delegate to a separate per-currency
// TOML file instead of declaring inline.
//
// SEP-0001 allows a currency entry to carry
// `toml="https://DOMAIN/.well-known/CURRENCY.toml"` as its ONLY field, so such
// an entry has no code or issuer to match against. Assay does not follow those
// links yet, which means a non-zero count here is the difference between "this
// domain did not claim the asset" and "this domain may have claimed it in a
// document we did not read". Those must never be reported the same way.
func (d *Doc) LinkedCurrencies() int {
	if d == nil {
		return 0
	}
	n := 0
	for _, c := range d.Currencies {
		if c.Toml != "" && c.Code == "" && c.Issuer == "" {
			n++
		}
	}
	return n
}

// Fetcher retrieves stellar.toml documents.
type Fetcher struct {
	HTTP      *http.Client
	UserAgent string
}

// NewFetcher returns a Fetcher with a bounded timeout and the redirect policy
// below.
func NewFetcher() *Fetcher {
	return &Fetcher{
		HTTP: &http.Client{
			Timeout:       15 * time.Second,
			CheckRedirect: CheckRedirect,
		},
		UserAgent: "assay/" + version + " (+https://github.com/use-assay/Assay)",
	}
}

// CheckRedirect is the redirect policy every Fetcher installs. It does two
// things, both deliberate:
//
//   - It bounds the chain at MaxRedirects rather than following whatever the
//     client's default is.
//   - It refuses a redirect that leaves the requested host's namespace. A
//     stellar.toml is a claim made by the domain in home_domain; if a redirect
//     could relocate the fetch to an unrelated host, that host's document would
//     be recorded as this domain's claim, and home_domain is attacker-
//     controlled free text. The final host is named in the error so a reader can
//     see where the fetch was being sent.
//
// The policy test is one-directional: the target must be the requested host or
// a subdomain of it. That admits the common apex-to-www move (circle.com →
// www.circle.com) while refusing a hop from a subdomain up to a parent domain,
// which may be a shared host whose content another party controls. See
// docs/checks.md for the reasoning.
func CheckRedirect(req *http.Request, via []*http.Request) error {
	if len(via) >= MaxRedirects {
		return fmt.Errorf("stopped after %d redirects", MaxRedirects)
	}
	// net/http always supplies the chain so far; refuse rather than index an
	// empty slice if this is ever called directly.
	if len(via) == 0 {
		return fmt.Errorf("redirect with no preceding request")
	}
	origin := via[0].URL.Hostname()
	final := req.URL.Hostname()
	if !withinRequestedSite(origin, final) {
		return fmt.Errorf("cross-host redirect from %s to %s", origin, final)
	}
	return nil
}

// withinRequestedSite reports whether final is origin itself or a subdomain of
// it, comparing labels case-insensitively and ignoring the root-trailing dot.
func withinRequestedSite(origin, final string) bool {
	origin = normalizeHost(origin)
	final = normalizeHost(final)
	if origin == "" || final == "" {
		return false
	}
	return final == origin || strings.HasSuffix(final, "."+origin)
}

// normalizeHost lowercases a host and strips a single trailing root dot, so
// "Circle.COM." and "circle.com" compare equal.
func normalizeHost(h string) string {
	return strings.ToLower(strings.TrimSuffix(h, "."))
}

// URLFor returns the SEP-1 well-known location for a domain.
func URLFor(domain string) string {
	return "https://" + strings.TrimSuffix(domain, "/") + "/.well-known/stellar.toml"
}

// Fetch retrieves and parses the stellar.toml for domain.
func (f *Fetcher) Fetch(ctx context.Context, domain string) (*Doc, error) {
	if domain == "" {
		return nil, ErrNoDomain
	}
	target := URLFor(domain)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", f.UserAgent)

	resp, err := f.HTTP.Do(req)
	if err != nil {
		return nil, fmt.Errorf("sep1: fetch %s: %w", target, err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("sep1: fetch %s: status %d", target, resp.StatusCode)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, MaxBody))
	if err != nil {
		return nil, fmt.Errorf("sep1: read %s: %w", target, err)
	}

	doc, err := Parse(body)
	if err != nil {
		return nil, fmt.Errorf("sep1: parse %s: %w", target, err)
	}
	doc.URL = resp.Request.URL.String()
	doc.FetchedAt = time.Now().UTC()
	return doc, nil
}

// Parse decodes stellar.toml bytes.
func Parse(b []byte) (*Doc, error) {
	var d Doc
	if err := toml.Unmarshal(b, &d); err != nil {
		return nil, err
	}
	return &d, nil
}
