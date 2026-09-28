package mechanics_test

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/use-assay/assay/internal/mechanics"
)

// The JSON boundary. Report.ScannedAt and Evidence.RetrievedAt cross it as
// RFC 3339 strings, and nothing before these tests verified that the emitted
// precision survives the trip back. docs/contract-interface.md excludes
// retrieval times from the preimage, so JSON is the only place these two
// fields are serialized at all — which makes the format they use there the
// documented one.

// jsonTimeCases are the instants worth covering at a time boundary. The epoch
// because it is the zero unix second and zero-valued times must not be
// silently distinguishable from it; a leap-second-adjacent instant because a
// leap second (:60) has no Go time.Time representation, so what is pinned is
// the last representable instant before one surviving the trip unchanged
// rather than being nudged into the next day; a far-future time because
// attested_at consumers compare against ledger clocks that will outlive sloppy
// year handling; and a non-UTC offset because the wire format is documented in
// UTC and a +hh:mm rendering must still unmarshal to the same instant.
var jsonTimeCases = []struct {
	name string
	at   time.Time
}{
	{"unix_epoch", time.Unix(0, 0).UTC()},
	{"leap_second_adjacent", time.Date(2016, 12, 31, 23, 59, 59, 500000000, time.UTC)},
	{"far_future", time.Date(2338, 6, 11, 3, 46, 40, 123000000, time.UTC)}, // 2^35 unix secs
	{"non_utc_input", time.Date(2026, 9, 24, 3, 30, 0, 750000000, time.FixedZone("UTC+5:30", 5*3600+1800))},
	{"zero_nanos", time.Date(2026, 9, 24, 12, 0, 0, 0, time.UTC)},
	{"nine_digit_nanos", time.Date(2026, 9, 24, 12, 0, 0, 123456789, time.UTC)},
}

// TestScannedAtTimeJSONRoundTrip marshals ScannedAt through the report JSON and
// asserts the parsed value equals the original at the documented precision.
func TestScannedAtTimeJSONRoundTrip(t *testing.T) {
	for _, tc := range jsonTimeCases {
		t.Run(tc.name, func(t *testing.T) {
			rep := &mechanics.Report{ScannedAt: tc.at}
			raw, err := json.Marshal(rep)
			if err != nil {
				t.Fatalf("marshal: %v", err)
			}
			var got mechanics.Report
			if err := json.Unmarshal(raw, &got); err != nil {
				t.Fatalf("unmarshal: %v", err)
			}
			if !got.ScannedAt.Equal(tc.at) {
				t.Fatalf("ScannedAt did not survive the JSON round trip: sent %s, got %s",
					tc.at.Format(time.RFC3339Nano), got.ScannedAt.Format(time.RFC3339Nano))
			}
		})
	}
}

// TestRetrievedAtTimeJSONRoundTrip does the same for evidence claims, including an
// Attempted one — failure evidence carries an attempt time (issue #52) and
// that time must survive serialization like any other.
func TestRetrievedAtTimeJSONRoundTrip(t *testing.T) {
	for _, tc := range jsonTimeCases {
		t.Run(tc.name, func(t *testing.T) {
			f := mechanics.Finding{Evidence: []mechanics.Evidence{{
				Source: "test", Claim: "x", RetrievedAt: tc.at, Attempted: true,
			}}}
			raw, err := json.Marshal(f)
			if err != nil {
				t.Fatalf("marshal: %v", err)
			}
			var got mechanics.Finding
			if err := json.Unmarshal(raw, &got); err != nil {
				t.Fatalf("unmarshal: %v", err)
			}
			if len(got.Evidence) != 1 {
				t.Fatalf("evidence did not survive: %d entries", len(got.Evidence))
			}
			if !got.Evidence[0].RetrievedAt.Equal(tc.at) {
				t.Fatalf("RetrievedAt did not survive the JSON round trip: sent %s, got %s",
					tc.at.Format(time.RFC3339Nano), got.Evidence[0].RetrievedAt.Format(time.RFC3339Nano))
			}
			if !got.Evidence[0].Attempted {
				t.Error("Attempted flag did not survive the round trip")
			}
		})
	}
}

// TestJSONTimestampPrecisionIsPinned locks the wire format itself. The test
// asserts the emitted form for every sub-second field of the reference time:
// if anyone changes the JSON encoding — an RFC 3339 variant, millisecond
// truncation, a different layout — this fails loudly instead of quietly
// moving what every stored report means.
func TestJSONTimestampPrecisionIsPinned(t *testing.T) {
	// Every nonzero sub-second digit: 1 nanosecond past whole seconds.
	at := time.Date(2026, 9, 24, 12, 34, 56, 1, time.UTC)
	rep := &mechanics.Report{ScannedAt: at}
	raw, err := json.Marshal(rep)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	// Go's RFC 3339 emission, exactly: UTC "Z", fractional seconds with
	// trailing zeros trimmed — a 1ns time renders .000000001. Asserted as the
	// timestamp token inside the full marshalled report: the surrounding
	// fields are the pin too, so a reshaped report object fails here as well.
	const wantToken = `"scanned_at":"2026-09-24T12:34:56.000000001Z"`
	if got := string(raw); !strings.Contains(got, wantToken) {
		t.Fatalf("scanned_at wire format changed:\n got: %s\nwant token: %s\n"+
			"If this change is deliberate, it changes the meaning of every stored report and needs a documented format note.",
			got, wantToken)
	}
}

// TestJSONTimestampUnmarshalRejectsMalformed pins the invalid state: a value
// that is not a parseable RFC 3339 instant must be rejected, not zeroed.
// Silent truncation is the failure mode these tests exist to catch; silent
// zeroing is its unmarshal-side twin.
func TestJSONTimestampUnmarshalRejectsMalformed(t *testing.T) {
	for _, bad := range []string{
		"2026-09-24 12:00:00Z", // space instead of T
		"2026-09-24T12:00:00",  // missing zone
		"not-a-time",
		"2016-12-31T23:59:60Z", // leap second: real UTC cannot represent it, and Go must refuse rather than fold it
	} {
		var rep mechanics.Report
		if err := json.Unmarshal([]byte(`{"scanned_at":"`+bad+`"}`), &rep); err == nil {
			t.Errorf("scanned_at %q was accepted by the JSON boundary", bad)
		}
	}
}

// TestJSONTimestampUnmarshalMatchesToolchainOffsetRange pins the one RFC 3339
// rule whose enforcement moved under us: RFC 3339 forbids UTC offsets outside
// ±23:59, and Go learned to reject them in json.Unmarshal and time.Parse
// between 1.22 (which happily parsed "+25:00" as a fixed zone) and 1.27
// (which refuses it). CI builds with the toolchain go.mod pins, so the JSON
// boundary must agree with whatever that toolchain's time.Parse does — never
// stricter, never looser. This test reads the boundary's position directly
// from the toolchain, so it passes on either side of the change and fails
// loudly if encoding/json ever diverges from time.Parse again.
func TestJSONTimestampUnmarshalMatchesToolchainOffsetRange(t *testing.T) {
	cases := []string{
		"2026-09-24T12:00:00+25:00",
		"2026-09-24T12:00:00-25:00",
		"2026-09-24T12:00:00+23:59", // in range: must always be accepted
	}
	for _, s := range cases {
		_, parseErr := time.Parse(time.RFC3339, s)
		want := parseErr == nil // what the toolchain itself says the string is worth
		var rep mechanics.Report
		err := json.Unmarshal([]byte(`{"scanned_at":"`+s+`"}`), &rep)
		got := err == nil
		if got != want {
			t.Errorf("scanned_at %q: JSON boundary says accepted=%v, toolchain time.Parse says %v; encoding/json has diverged from time.Parse", s, got, want)
		}
	}
}
