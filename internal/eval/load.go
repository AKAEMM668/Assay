package eval

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/use-assay/assay/internal/horizon"
	"github.com/use-assay/assay/internal/mechanics"
	"github.com/use-assay/assay/internal/sep1"
	"github.com/use-assay/assay/internal/stellarexpert"
)

// fixtureTime is the capture instant used for fixture replay. A live scan
// records a separate completion time per source; a replay has no latency, so
// every source answers at the same instant — which is what the capture itself
// looked like. It is excluded from evidence_hash, so the exact value does not
// affect any recorded hash.
var fixtureTime = time.Date(2026, 8, 10, 0, 0, 0, 0, time.UTC)

// LoadSubject rebuilds a mechanics.Subject from captured fixtures, using the
// same decoders the live fetchers use. Nothing here touches the network.
//
// This is the single loader for the labelled corpus: the eval tests and the
// eval command both call it, so a fixture that parses for one parses for the
// other, and a result cannot drift because a third-party API had a bad day.
func LoadSubject(fixturesDir, dir string) (*mechanics.Subject, error) {
	base := filepath.Join(fixturesDir, dir)

	var stat horizon.AssetStat
	if err := readJSON(filepath.Join(base, "asset.json"), &stat); err != nil {
		return nil, err
	}
	var acct horizon.Account
	if err := readJSON(filepath.Join(base, "account.json"), &acct); err != nil {
		return nil, err
	}

	s := &mechanics.Subject{
		Asset:           mechanics.Asset{Code: stat.AssetCode, Issuer: stat.AssetIssuer},
		Stat:            &stat,
		StatFetchedAt:   fixtureTime,
		Issuer:          &acct,
		IssuerFetchedAt: fixtureTime,
		ScannedAt:       fixtureTime,
	}

	if acct.HomeDomain != "" {
		s.TomlURL = sep1.URLFor(acct.HomeDomain)
		s.TomlAttemptedAt = fixtureTime
	}
	if b, err := os.ReadFile(filepath.Join(base, "stellar.toml")); err == nil {
		doc, err := sep1.Parse(b)
		if err != nil {
			return nil, fmt.Errorf("parse %s stellar.toml: %w", dir, err)
		}
		doc.URL = s.TomlURL
		s.Toml = doc
	} else if st, err := os.ReadFile(filepath.Join(base, "stellar.toml.status")); err == nil {
		s.TomlErr = "status " + strings.TrimSpace(string(st))
	}

	s.DirectoryURL = "https://api.stellar.expert/explorer/directory/" + stat.AssetIssuer
	s.DirectoryAttemptedAt = fixtureTime
	if _, err := os.Stat(filepath.Join(base, "directory.json")); err == nil {
		var e stellarexpert.DirectoryEntry
		if err := readJSON(filepath.Join(base, "directory.json"), &e); err != nil {
			return nil, err
		}
		s.Directory = &e
		s.DirectoryFetchedAt = fixtureTime
	}
	s.BlockedURL = "https://api.stellar.expert/explorer/directory/blocked-domains/"
	if acct.HomeDomain != "" {
		s.BlockedURL += acct.HomeDomain
	}
	s.BlockedAttemptedAt = fixtureTime
	if _, err := os.Stat(filepath.Join(base, "blocked.json")); err == nil {
		var b stellarexpert.BlockedDomain
		if err := readJSON(filepath.Join(base, "blocked.json"), &b); err != nil {
			return nil, err
		}
		s.Blocked = &b
		s.BlockedFetchedAt = fixtureTime
	}
	return s, nil
}

func readJSON(path string, out any) error {
	b, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	if err := json.Unmarshal(b, out); err != nil {
		return fmt.Errorf("decode %s: %w", path, err)
	}
	return nil
}
