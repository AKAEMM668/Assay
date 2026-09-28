package scan_test

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/use-assay/assay/internal/mechanics"
	"github.com/use-assay/assay/internal/scan"
)

func TestParseAsset(t *testing.T) {
	const issuer = "GA5ZSEJYB37JRC5AVCIA5MOP4RHTM335X2KGX3IHOJAPP5RE34K4KZVN"

	t.Run("valid", func(t *testing.T) {
		for _, in := range []string{
			"USDC-" + issuer,
			"  USDC-" + issuer + "  ",
			// StellarExpert renders assets with a trailing sequence suffix.
			"USDC-" + issuer + "-1",
		} {
			a, err := scan.ParseAsset(in)
			if err != nil {
				t.Fatalf("ParseAsset(%q): %v", in, err)
			}
			if a.Code != "USDC" || a.Issuer != issuer {
				t.Errorf("ParseAsset(%q) = %+v", in, a)
			}
		}
	})

	t.Run("rejected", func(t *testing.T) {
		for _, in := range []string{
			"",
			"USDC",
			"-" + issuer,
			"USDC-NOTAKEY",
			// Lowercase is outside the base32 alphabet Stellar keys use, so
			// accepting it would let a lookalike issuer through.
			"USDC-" + "ga5zsejyb37jrc5avcia5mop4rhtm335x2kgx3ihojapp5re34k4kzvn",
			"TOOLONGASSETCODE-" + issuer,
			"US DC-" + issuer,
		} {
			if _, err := scan.ParseAsset(in); !errors.Is(err, scan.ErrBadAsset) {
				t.Errorf("ParseAsset(%q) error = %v, want ErrBadAsset", in, err)
			}
		}
	})
}

// fakeSources stands up stand-ins for Horizon, StellarExpert, and the issuer's
// stellar.toml. Every handler sleeps a different, nonzero amount so a real
// scan (not a hand-built Subject) produces genuinely staggered fetch times.
type fakeSources struct {
	horizon *httptest.Server
	expert  *httptest.Server
	toml    *httptest.Server
}

const (
	scanIssuer   = "GA5ZSEJYB37JRC5AVCIA5MOP4RHTM335X2KGX3IHOJAPP5RE34K4KZVN"
	scanHomeDom  = "centre.test"
	horizonDelay = 40 * time.Millisecond
	tomlDelay    = 30 * time.Millisecond
	blockedDelay = 20 * time.Millisecond
	dirDelay     = 10 * time.Millisecond
)

func newFakeSources(t *testing.T) *fakeSources {
	t.Helper()
	fs := &fakeSources{}

	fs.horizon = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(horizonDelay)
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/assets":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"_embedded": map[string]any{
					"records": []map[string]any{{
						"asset_type":   "credit_alphanum4",
						"asset_code":   "USDC",
						"asset_issuer": scanIssuer,
						"flags":        map[string]bool{},
					}},
				},
			})
		case "/accounts/" + scanIssuer:
			_ = json.NewEncoder(w).Encode(map[string]any{
				"account_id":  scanIssuer,
				"home_domain": scanHomeDom,
				"flags":       map[string]bool{},
			})
		default:
			http.NotFound(w, r)
		}
	}))

	fs.expert = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/explorer/directory/blocked-domains/" + scanHomeDom:
			time.Sleep(blockedDelay)
			_, _ = w.Write([]byte(`{"domain":"` + scanHomeDom + `","blocked":false}`))
		case "/explorer/directory/" + scanIssuer:
			// The directory answers 200-with-empty-body for an unlisted address.
			time.Sleep(dirDelay)
			_, _ = w.Write([]byte(`{}`))
		default:
			http.NotFound(w, r)
		}
	}))

	fs.toml = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(tomlDelay)
		_, _ = w.Write([]byte("[[CURRENCIES]]\ncode=\"USDC\"\nissuer=\"" + scanIssuer + "\"\n"))
	}))

	t.Cleanup(func() {
		fs.horizon.Close()
		fs.expert.Close()
		fs.toml.Close()
	})
	return fs
}

// TestSubjectRecordsPerSourceFetchTimes is the acceptance test for per-source
// observation timestamps. It drives a real scan over sources that answer at
// provably different instants, then asserts the report's evidence carries the
// time of the source each claim came from — not one shared start-of-scan time.
func TestSubjectRecordsPerSourceFetchTimes(t *testing.T) {
	fs := newFakeSources(t)

	sc := scan.New()
	sc.Horizon.BaseURL = fs.horizon.URL
	sc.Expert.BaseURL = fs.expert.URL
	sc.Toml.HTTP.Transport = &singleHostTransport{host: strings.TrimPrefix(fs.toml.URL, "http://")}

	start := time.Now().UTC().Add(-time.Second) // slack for clock scheduling
	sub, err := sc.Subject(context.Background(), mustParse(t, "USDC-"+scanIssuer))
	if err != nil {
		t.Fatalf("Subject: %v", err)
	}

	// Order of operations in Subject: horizon assets, horizon account, toml,
	// blocked-domains, directory. Each fetch sleeps a different amount, so the
	// completion times must be strictly increasing in that order — a shared
	// start-of-scan timestamp cannot satisfy this.
	seq := []struct {
		name string
		at   time.Time
	}{
		{"StatFetchedAt (horizon assets)", sub.StatFetchedAt},
		{"IssuerFetchedAt (horizon account)", sub.IssuerFetchedAt},
		{"Toml.Doc.FetchedAt (stellar.toml)", sub.Toml.FetchedAt},
		{"BlockedFetchedAt (blocklist)", sub.BlockedFetchedAt},
		{"DirectoryFetchedAt (directory)", sub.DirectoryFetchedAt},
	}
	for i := 1; i < len(seq); i++ {
		if !seq[i].at.After(seq[i-1].at) {
			t.Errorf("%s (%s) is not after %s (%s): timestamps are not per-source",
				seq[i].name, seq[i].at.Format(time.RFC3339Nano),
				seq[i-1].name, seq[i-1].at.Format(time.RFC3339Nano))
		}
	}
	for _, e := range seq {
		if e.at.Before(start) {
			t.Errorf("%s = %s predates the scan", e.name, e.at.Format(time.RFC3339Nano))
		}
	}

	if sub.ScannedAt.After(sub.Toml.FetchedAt) {
		t.Errorf("ScannedAt (%s) is not the scan start: it comes after the toml completion (%s)",
			sub.ScannedAt.Format(time.RFC3339Nano), sub.Toml.FetchedAt.Format(time.RFC3339Nano))
	}
	if sub.TomlAttemptedAt.After(sub.Toml.FetchedAt) {
		t.Errorf("toml attempt time %s is after its completion time %s",
			sub.TomlAttemptedAt.Format(time.RFC3339Nano), sub.Toml.FetchedAt.Format(time.RFC3339Nano))
	}

	// Engine round trip: every success evidence claim carries its own source's
	// completion time, and the report's ScannedAt is the scan start.
	rep, err := sc.Engine.Run(context.Background(), sub)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if !rep.ScannedAt.Equal(sub.ScannedAt) {
		t.Errorf("Report.ScannedAt = %s, want the scan start %s",
			rep.ScannedAt.Format(time.RFC3339Nano), sub.ScannedAt.Format(time.RFC3339Nano))
	}
	want := map[string]time.Time{
		"horizon":                        sub.StatFetchedAt,
		"stellar.toml":                   sub.Toml.FetchedAt,
		"stellar.expert/blocked-domains": sub.BlockedFetchedAt,
		"stellar.expert/directory":       sub.DirectoryFetchedAt,
	}
	for _, ev := range rep.Evidence {
		wantAt, ok := want[ev.Source]
		if !ok {
			t.Errorf("unexpected evidence source %q", ev.Source)
			continue
		}
		if ev.Attempted {
			t.Errorf("success evidence for %s is marked Attempted", ev.Source)
		}
		if !ev.RetrievedAt.Equal(wantAt) {
			t.Errorf("%s evidence RetrievedAt = %s, want %s (that source's completion time)",
				ev.Source, ev.RetrievedAt.Format(time.RFC3339Nano), wantAt.Format(time.RFC3339Nano))
		}
	}
}

// TestSubjectFailureEvidenceCarriesAttemptTime covers the failure half of the
// semantics: a source that fails records the attempt time, and the resulting
// evidence is labelled Attempted so a program can tell an attempt from an
// answer without parsing the claim text.
func TestSubjectFailureEvidenceCarriesAttemptTime(t *testing.T) {
	fs := newFakeSources(t)

	// Swap the blocklist handler for a 503, and record when the scan asked.
	var attempted time.Time
	fs.expert.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/explorer/directory/blocked-domains/") {
			attempted = time.Now().UTC()
			http.Error(w, "boom", http.StatusServiceUnavailable)
			return
		}
		time.Sleep(dirDelay)
		_, _ = w.Write([]byte(`{}`))
	})

	sc := scan.New()
	sc.Horizon.BaseURL = fs.horizon.URL
	sc.Expert.BaseURL = fs.expert.URL
	sc.Toml.HTTP.Transport = &singleHostTransport{host: strings.TrimPrefix(fs.toml.URL, "http://")}

	start := time.Now().UTC()
	sub, err := sc.Subject(context.Background(), mustParse(t, "USDC-"+scanIssuer))
	end := time.Now().UTC()
	if err != nil {
		t.Fatalf("Subject: %v", err)
	}
	if sub.BlockedErr == "" {
		t.Fatal("expected the blocklist fetch to fail")
	}
	if sub.BlockedAttemptedAt.IsZero() {
		t.Fatal("failed fetch recorded no attempt time")
	}
	if !sub.BlockedFetchedAt.IsZero() {
		t.Error("failed fetch must not record a completion time")
	}
	// The attempt must be recorded inside the scan's wall-clock window, and
	// before the server goroutine saw the request it produced. (Equality is
	// not asserted against the handler's clock capture: the scan records the
	// attempt before sending, the server stamps on receipt, and the two
	// goroutines are only ordered, never simultaneous.)
	if sub.BlockedAttemptedAt.Before(start) || sub.BlockedAttemptedAt.After(end) {
		t.Errorf("recorded attempt time %s falls outside the scan window [%s, %s]",
			sub.BlockedAttemptedAt.Format(time.RFC3339Nano),
			start.Format(time.RFC3339Nano), end.Format(time.RFC3339Nano))
	}
	if sub.BlockedAttemptedAt.After(attempted) {
		t.Errorf("recorded attempt time %s is after the server received the request (%s)",
			sub.BlockedAttemptedAt.Format(time.RFC3339Nano), attempted.Format(time.RFC3339Nano))
	}

	rep, err := sc.Engine.Run(context.Background(), sub)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	var found bool
	for _, ev := range rep.Evidence {
		if ev.Source != "stellar.expert/blocked-domains" {
			continue
		}
		found = true
		if !ev.Attempted {
			t.Error("failure evidence is not marked Attempted; an attempt is not an answer")
		}
		if !ev.RetrievedAt.Equal(sub.BlockedAttemptedAt) {
			t.Errorf("failure evidence carries %s, want the attempt time %s",
				ev.RetrievedAt.Format(time.RFC3339Nano), sub.BlockedAttemptedAt.Format(time.RFC3339Nano))
		}
		if !strings.Contains(ev.Claim, "not retrievable") {
			t.Errorf("failure evidence claim does not read as a failure: %q", ev.Claim)
		}
	}
	if !found {
		t.Fatal("no evidence recorded for the unreachable blocklist")
	}
}

// singleHostTransport routes every request to one test host, so the sep1
// Fetcher — whose target URL is derived from the issuer's home_domain — can be
// pointed at an httptest server without changing sep1.URLFor.
type singleHostTransport struct{ host string }

func (t *singleHostTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	req = req.Clone(req.Context())
	u := *req.URL
	u.Scheme = "http"
	u.Host = t.host
	req.URL = &u
	return http.DefaultTransport.RoundTrip(req)
}

func mustParse(t *testing.T, s string) mechanics.Asset {
	t.Helper()
	a, err := scan.ParseAsset(s)
	if err != nil {
		t.Fatalf("ParseAsset(%q): %v", s, err)
	}
	return a
}
