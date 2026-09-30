package main

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/use-assay/assay/internal/mechanics"
)

func TestHistoryJSON(t *testing.T) {
	now := time.Date(2026, 9, 5, 12, 0, 0, 0, time.UTC)
	rep := &mechanics.Report{
		Asset: mechanics.Asset{Code: "AQUA", Issuer: "GBNZILSTVQZ4R7IKQDGHYGY2QXL5QOFJYQMXPKWRRM5PAV7Y4M67AQUA"},
		Evidence: []mechanics.Evidence{
			{
				Source:      "horizon",
				URL:         "https://horizon.stellar.org/assets?asset_code=AQUA&asset_issuer=GBNZILSTVQZ4R7IKQDGHYGY2QXL5QOFJYQMXPKWRRM5PAV7Y4M67AQUA",
				Claim:       "issuer flags: auth_required=false auth_revocable=false auth_immutable=false auth_clawback_enabled=false",
				RetrievedAt: mechanics.NewCanonicalTime(now),
			},
			{
				Source:      "stellar.expert/directory",
				URL:         "https://api.stellar.expert/explorer/directory/GBNZILSTVQZ4R7IKQDGHYGY2QXL5QOFJYQMXPKWRRM5PAV7Y4M67AQUA",
				Claim:       "listed as \"Zeam.Money\" (domain \"zeam.money\", tags: )",
				RetrievedAt: mechanics.NewCanonicalTime(now.Add(1 * time.Hour)),
			},
		},
	}

	want := []historyEntry{
		{
			Asset:      "AQUA-GBNZILSTVQZ4R7IKQDGHYGY2QXL5QOFJYQMXPKWRRM5PAV7Y4M67AQUA",
			Severity:   "clear",
			Transition: "unknown",
			Reason:     "issuer flags: auth_required=false auth_revocable=false auth_immutable=false auth_clawback_enabled=false",
			Time:       now,
		},
		{
			Asset:      "AQUA-GBNZILSTVQZ4R7IKQDGHYGY2QXL5QOFJYQMXPKWRRM5PAV7Y4M67AQUA",
			Severity:   "clear",
			Transition: "listed as",
			Reason:     "listed as \"Zeam.Money\" (domain \"zeam.money\", tags: )",
			Time:       now.Add(1 * time.Hour),
		},
	}

	got := history(rep)
	if len(got) != len(want) {
		t.Fatalf("history length = %d, want %d", len(got), len(want))
	}
	for i := range got {
		if got[i] != want[i] {
			t.Errorf("history[%d] = %+v, want %+v", i, got[i], want[i])
		}
	}
}

func TestHistoryJSONEmpty(t *testing.T) {
	if got := history(nil); len(got) != 0 {
		t.Fatalf("history(nil) = %d entries, want 0", len(got))
	}

	rep := &mechanics.Report{
		Asset: mechanics.Asset{Code: "AQUA", Issuer: "GBNZILSTVQZ4R7IKQDGHYGY2QXL5QOFJYQMXPKWRRM5PAV7Y4M67AQUA"},
	}
	if got := history(rep); len(got) != 0 {
		t.Fatalf("history(report with no evidence) = %d entries, want 0", len(got))
	}
}

func TestHistoryRaw(t *testing.T) {
	now := time.Date(2026, 9, 5, 12, 0, 0, 0, time.UTC)
	rep := &mechanics.Report{
		Asset: mechanics.Asset{Code: "AQUA", Issuer: "GBNZILSTVQZ4R7IKQDGHYGY2QXL5QOFJYQMXPKWRRM5PAV7Y4M67AQUA"},
		Evidence: []mechanics.Evidence{
			{
				Source:      "horizon",
				URL:         "https://horizon.stellar.org/assets?asset_code=AQUA&asset_issuer=GBNZILSTVQZ4R7IKQDGHYGY2QXL5QOFJYQMXPKWRRM5PAV7Y4M67AQUA",
				Claim:       "issuer flags: auth_required=false auth_revocable=false auth_immutable=false auth_clawback_enabled=false",
				RetrievedAt: mechanics.NewCanonicalTime(now),
			},
		},
	}

	got := history(rep)
	for _, h := range got {
		if h.Transition != "unknown" {
			t.Errorf("transition = %q, want unknown", h.Transition)
		}
		if h.Reason == "" {
			t.Errorf("history entry has empty reason: %+v", h)
		}
	}
}

func TestTransition(t *testing.T) {
	cases := []struct {
		claim    string
		expected string
	}{
		{"issuer flags: auth_required=false auth_revocable=false auth_immutable=false auth_clawback_enabled=false", "unknown"},
		{"listed as \"Zeam.Money\" (domain \"zeam.money\", tags: )", "listed as"},
		{"domain unverified", "unverified"},
		{"not retrievable: status 429", "not retrievable"},
		{"domain blocked", "blocked"},
		{"malicious listing found", "malicious"},
		{"", "unknown"},
		{"something completely different", "unknown"},
	}

	for _, tc := range cases {
		if got := transition(tc.claim); got != tc.expected {
			t.Errorf("transition(%q) = %q, want %q", tc.claim, got, tc.expected)
		}
	}
}

func TestHistoryJSONMarshal(t *testing.T) {
	now := time.Date(2026, 9, 5, 12, 0, 0, 0, time.UTC)
	hist := []historyEntry{
		{
			Asset:      "USDC-GA5ZSEJYB37JRC5AVCIA5MOP4RHTM335X2KGX3IHOJAPP5RE34K4KZVN",
			Severity:   "medium",
			Transition: "unknown",
			Reason:     "issuer flags: auth_required=false auth_revocable=true auth_immutable=false auth_clawback_enabled=false",
			Time:       now,
		},
	}

	b, err := json.Marshal(hist)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var round []historyEntry
	if err := json.Unmarshal(b, &round); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if len(round) != 1 || round[0].Asset != hist[0].Asset || round[0].Transition != hist[0].Transition {
		t.Errorf("JSON round-trip mismatch: %s", b)
	}
}
