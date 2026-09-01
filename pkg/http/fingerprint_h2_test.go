package http

import (
	"testing"

	"github.com/pagpeter/trackme/pkg/types"
)

func TestGetSettingsFingerprint_PreservesUnknownSettingIDs(t *testing.T) {
	frames := []types.ParsedFrame{
		{
			Type: "SETTINGS",
			Settings: []string{
				"HEADER_TABLE_SIZE = 65536",
				"UNKNOWN_SETTING_43690 = 0",
				"INITIAL_WINDOW_SIZE = 6291456",
			},
		},
	}

	got := getSettingsFingerprint(frames)
	want := "1:65536;43690:0;4:6291456"

	if got != want {
		t.Fatalf("unexpected settings fingerprint:\nwant: %s\ngot:  %s", want, got)
	}
}

func TestGetSettingsFingerprint_InvalidUnknownSettingID(t *testing.T) {
	frames := []types.ParsedFrame{
		{
			Type: "SETTINGS",
			Settings: []string{
				"UNKNOWN_SETTING_not-a-number = 1",
			},
		},
	}

	got := getSettingsFingerprint(frames)
	if got != "error" {
		t.Fatalf("expected error fingerprint, got: %s", got)
	}
}
