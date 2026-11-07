package geoip

import (
	"os"
	"path/filepath"
	"testing"

	"net/netip"
)

func TestLoadCountryDBAndLookup(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "dbip-country-lite.csv")
	content := "\"1.0.0.0\",\"1.0.0.255\",\"OC\",\"Oceania\",\"AU\",\"0\",\"Australia\"\n" +
		"\"8.8.8.0\",\"8.8.8.255\",\"NA\",\"North America\",\"US\",\"0\",\"United States\"\n"
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}

	db, err := LoadCountryDB(path)
	if err != nil {
		t.Fatalf("LoadCountryDB() error = %v", err)
	}

	geo, ok := db.Lookup(netip.MustParseAddr("8.8.8.8"))
	if !ok {
		t.Fatal("expected lookup hit")
	}
	if geo.CountryCode != "US" || geo.CountryName != "United States" {
		t.Fatalf("unexpected geo lookup: %+v", geo)
	}

	if _, ok := db.Lookup(netip.MustParseAddr("203.0.113.7")); ok {
		t.Fatal("expected lookup miss")
	}
}
