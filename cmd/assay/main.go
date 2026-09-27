// Command assay scans Stellar assets for issuer trap mechanics.
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/use-assay/assay/internal/api"
	"github.com/use-assay/assay/internal/attest"
	// Aliased because this file already has a local history() for the CLI's
	// evidence view; this package is the persisted observation store behind the
	// HTTP endpoint, a different thing.
	historystore "github.com/use-assay/assay/internal/history"
	"github.com/use-assay/assay/internal/mechanics"
	"github.com/use-assay/assay/internal/scan"
)

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "assay:", err)
		os.Exit(1)
	}
}

func usage() {
	fmt.Fprint(os.Stderr, `usage:
  assay scan CODE-ISSUER          classify one asset and print the report as JSON
  assay attestation CODE-ISSUER   print the on-chain attest() arguments for one asset
  assay history [-guarantee] [-raw] CODE-ISSUER
                                  print the asset's observation history
  assay serve [-addr]             serve the HTTP API and UI

Every command that scans accepts:
  -cache-directory-ttl D   reuse a curated directory answer for D (0 disables)
  -cache-blocklist-ttl D   reuse a blocklist answer for D (0 disables)
  -no-cache                re-fetch curated sources on every scan
  assay serve [-addr] [-history PATH]
                                  serve the HTTP API and UI
`)
}

func run(args []string) error {
	if len(args) == 0 {
		usage()
		return fmt.Errorf("no command given")
	}

	log := slog.New(slog.NewTextHandler(os.Stderr, nil))

	switch args[0] {
	case "scan":
		return runScan(args[1:])
	case "attestation":
		return runAttestation(args[1:])
	case "history":
		return runHistory(args[1:])
	case "serve":
		return runServe(args[1:], log)
	default:
		usage()
		return fmt.Errorf("unknown command %q", args[0])
	}
}

func runScan(args []string) error {
	fs := flag.NewFlagSet("scan", flag.ContinueOnError)
	cache := cacheFlags(fs)
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 1 {
		return fmt.Errorf("scan takes exactly one asset (CODE-ISSUER)")
	}
	asset, err := scan.ParseAsset(fs.Arg(0))
	if err != nil {
		return err
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	report, err := scan.NewWithOptions(cache()).Scan(ctx, asset)
	if err != nil {
		return err
	}

	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	return enc.Encode(report)
}

// cacheFlags registers the consumed-signal cache flags shared by every command
// that scans, and returns a constructor for the Scanner options they describe.
//
// Caching is on by default because every scan consumes a free, rate-limited
// service, and re-fetching an answer that has not changed is discourteous to
// its operators. The flags exist so a deployment can trade the other way — a
// one-shot scan can afford to re-fetch everything — without the choice being
// hidden in a constant. Whatever the choice, Evidence.RetrievedAt is the time
// the source produced its answer, so a report never reads as fresher than its
// data. See docs/caching.md.
func cacheFlags(fs *flag.FlagSet) func() scan.Options {
	def := scan.DefaultOptions()
	directory := fs.Duration("cache-directory-ttl", def.ReputationDirectoryTTL,
		"how long a curated directory answer may be reused (0 disables)")
	blocklist := fs.Duration("cache-blocklist-ttl", def.ReputationBlocklistTTL,
		"how long a blocklist answer may be reused (0 disables); lower it to tighten a safety-critical window")
	off := fs.Bool("no-cache", false,
		"re-fetch curated sources on every scan instead of serving a cached answer")
	return func() scan.Options {
		return scan.Options{
			ReputationDirectoryTTL: *directory,
			ReputationBlocklistTTL: *blocklist,
			NoReputationCache:      *off,
		}
	}
}

// runAttestation prints the arguments of an on-chain attest() call for one
// asset, derived from a live scan.
//
// It deliberately does not submit anything. Signing belongs to whoever holds
// the attester key, and keeping derivation separate from submission means the
// numbers going on-chain can be inspected — and the evidence hash independently
// recomputed from -preimage — before a key ever touches them.
func runAttestation(args []string) error {
	fs := flag.NewFlagSet("attestation", flag.ContinueOnError)
	cache := cacheFlags(fs)
	preimage := fs.Bool("preimage", false, "include the canonical bytes evidence_hash commits to")
	raw := fs.Bool("raw", false, "print only the attest() arguments, tab-separated, for scripting")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 1 {
		return fmt.Errorf("attestation takes exactly one asset (CODE-ISSUER)")
	}
	asset, err := scan.ParseAsset(fs.Arg(0))
	if err != nil {
		return err
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	report, err := scan.NewWithOptions(cache()).Scan(ctx, asset)
	if err != nil {
		return err
	}
	params, err := attest.FromReport(report)
	if err != nil {
		return err
	}

	if *raw {
		_, err := fmt.Printf("%d\t%d\t%s\n", params.Severity, params.Flags, params.EvidenceHash)
		return err
	}
	if !*preimage {
		params.Preimage = ""
	}

	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	return enc.Encode(params)
}

func runHistory(args []string) error {
	fs := flag.NewFlagSet("history", flag.ContinueOnError)
	cache := cacheFlags(fs)
	guarantee := fs.Bool("guarantee", false, "exit non-zero when there is no history")
	raw := fs.Bool("raw", false, "print only the history, tab-separated, for scripting")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 1 {
		return fmt.Errorf("history takes exactly one asset (CODE-ISSUER)")
	}

	asset, err := scan.ParseAsset(fs.Arg(0))
	if err != nil {
		return err
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	report, err := scan.NewWithOptions(cache()).Scan(ctx, asset)
	if err != nil {
		return err
	}

	hist := history(report)

	if len(hist) == 0 {
		msg := "assay history: no observations for " + asset.String()
		if *raw {
			fmt.Println(msg)
			if *guarantee {
				return fmt.Errorf("no history")
			}
			return nil
		}
		fmt.Println(msg)
		if *guarantee {
			return fmt.Errorf("no history")
		}
		return nil
	}

	if *raw {
		for _, h := range hist {
			fmt.Printf("%s\t%s\t%s\t%s\n", h.Asset, h.Severity, h.Transition, h.Reason)
		}
		return nil
	}

	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	return enc.Encode(hist)
}

// history extracts the observation history from a report. The observations are
// the evidence entries, in time order. When there are none, it returns an empty
// slice so the caller can print the clear message.
func history(rep *mechanics.Report) []historyEntry {
	if rep == nil {
		return nil
	}
	hist := make([]historyEntry, 0, len(rep.Evidence))
	for _, e := range rep.Evidence {
		hist = append(hist, historyEntry{
			Asset:      rep.Asset.String(),
			Severity:   rep.Severity.String(),
			Transition: transition(e.Claim),
			Reason:     e.Claim,
			Time:       e.RetrievedAt,
		})
	}
	return hist
}

// transition reduces a plain-language evidence claim to the term the
// consumer prints: whatever the issuer was observed doing, or unknown when a
// source did not answer.
func transition(claim string) string {
	if claim == "" {
		return "unknown"
	}
	low := strings.ToLower(claim)
	for _, s := range candidateTransitions {
		if strings.Contains(low, s) {
			return s
		}
	}
	return "unknown"
}

// candidateTransitions is the set of ways an observation can read in this
// project. It is deliberately small: the history view does not re-derive the
// verdict, it only reports what each observation says.
var candidateTransitions = []string{
	"malicious",
	"listed as",
	"blocked",
	"unverified",
	"not retrievable",
	"credits",
	"claims",
	"borrow",
	"pay",
}

type historyEntry struct {
	Asset      string    `json:"asset"`
	Severity   string    `json:"severity"`
	Transition string    `json:"transition"`
	Reason     string    `json:"reason"`
	Time       time.Time `json:"time"`
}

func runServe(args []string, log *slog.Logger) error {
	fs := flag.NewFlagSet("serve", flag.ContinueOnError)
	cache := cacheFlags(fs)
	addr := fs.String("addr", ":8080", "listen address")
	historyPath := fs.String("history", "",
		"path to the observation history log (JSON Lines); empty keeps history in memory only")
	if err := fs.Parse(args); err != nil {
		return err
	}

	// The cache lives as long as the server process, which is where it earns
	// its keep: repeated scans of the same issuer reuse an answer instead of
	// re-reading a free service on every request.
	srv := &http.Server{
		Addr:              *addr,
		Handler:           api.NewServerWithScanner(scan.NewWithOptions(cache()), log).Handler(),
	srv := api.NewServer(log)
	if *historyPath != "" {
		store, err := historystore.Open(*historyPath)
		if err != nil {
			return err
		}
		srv.History = store
	}

	httpSrv := &http.Server{
		Addr:              *addr,
		Handler:           srv.Handler(),
		ReadHeaderTimeout: 10 * time.Second,
	}
	log.Info("assay listening", "addr", *addr, "history", *historyPath)
	return httpSrv.ListenAndServe()
}
