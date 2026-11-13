package scan

import (
	"reflect"
	"strings"
	"testing"
)

func TestParsePortSpec(t *testing.T) {
	cases := []struct {
		spec string
		tcp  []uint16
		udp  []uint16
	}{
		{"80", []uint16{80}, nil},
		{"80,443", []uint16{80, 443}, nil},
		{"80,443,8080-8082", []uint16{80, 443, 8080, 8081, 8082}, nil},
		{"U:161", nil, []uint16{161}},
		{"53,U:53", []uint16{53}, []uint16{53}},
		{"udp:123-124", nil, []uint16{123, 124}},
		{"tcp:22", []uint16{22}, nil},
		{" 22 , 23 ", []uint16{22, 23}, nil},
		{"443,443,443", []uint16{443}, nil},            // dedupe
		{"9000-8998", []uint16{8998, 8999, 9000}, nil}, // reversed range
	}
	for _, c := range cases {
		got, err := ParsePortSpec(c.spec)
		if err != nil {
			t.Fatalf("%q: unexpected error %v", c.spec, err)
		}
		if !reflect.DeepEqual(got.TCP, c.tcp) {
			t.Errorf("%q: tcp = %v, want %v", c.spec, got.TCP, c.tcp)
		}
		if !reflect.DeepEqual(got.UDP, c.udp) {
			t.Errorf("%q: udp = %v, want %v", c.spec, got.UDP, c.udp)
		}
	}
}

func TestParsePortSpecAll(t *testing.T) {
	got, err := ParsePortSpec("all")
	if err != nil {
		t.Fatal(err)
	}
	if len(got.TCP) != 65536 {
		t.Errorf("all: %d ports, want 65536", len(got.TCP))
	}
	if got.TCP[0] != 0 || got.TCP[65535] != 65535 {
		t.Error("all: range endpoints wrong")
	}
}

func TestParsePortSpecErrors(t *testing.T) {
	for _, spec := range []string{"", "  ", "70000", "abc", "80-", "-80", "80-999999"} {
		if _, err := ParsePortSpec(spec); err == nil {
			t.Errorf("%q: expected an error", spec)
		}
	}
}

func TestPortSetStringRoundTrip(t *testing.T) {
	specs := []string{"80,443,8080-8082,U:53,U:161-162", "22,25", "U:69", "1-3,5,7-9,U:500"}
	for _, spec := range specs {
		ps, err := ParsePortSpec(spec)
		if err != nil {
			t.Fatalf("%q: %v", spec, err)
		}
		again, err := ParsePortSpec(ps.String())
		if err != nil {
			t.Fatalf("%q round-trip: %v", ps.String(), err)
		}
		if !reflect.DeepEqual(ps.TCP, again.TCP) || !reflect.DeepEqual(ps.UDP, again.UDP) {
			t.Errorf("%q round-trip mismatch: %v -> %q -> %v", spec, ps, ps.String(), again)
		}
	}
}

func TestPresetsParse(t *testing.T) {
	for _, name := range PresetNames() {
		spec, ok := LookupPreset(name)
		if !ok {
			t.Fatalf("preset %q missing", name)
		}
		ps, err := ParsePortSpec(spec)
		if err != nil {
			t.Errorf("preset %q: %v", name, err)
			continue
		}
		if ps.Total() == 0 {
			t.Errorf("preset %q is empty", name)
		}
	}
}

func TestPresetAliases(t *testing.T) {
	for alias, want := range map[string]string{
		"minimal":    "minimal",
		"MIN":        "minimal",
		"default":    "minimal",
		"enterprise": "enterprise",
		"db":         "database",
		"ics":        "scada",
		"all":        "all",
		"minimal ":   "minimal",
	} {
		spec, ok := LookupPreset(alias)
		if !ok {
			t.Fatalf("alias %q not resolved", alias)
		}
		wantSpec, _ := LookupPreset(want)
		if spec != wantSpec {
			t.Errorf("alias %q resolved to %q, want the %q preset", alias, spec, want)
		}
	}
	if _, ok := LookupPreset("nope-not-a-preset"); ok {
		t.Error("unknown preset should not resolve")
	}
}

func TestLoadGobyPresets(t *testing.T) {
	path := t.TempDir() + "/config.json"
	content := `{"ports":[{"title":"Enterprise","value":"21,22,80,U:161"},{"title":"scanConfig.All","value":"0-65535"}],"rate":100}`
	if err := writeFile(path, content); err != nil {
		t.Fatal(err)
	}
	presets, err := LoadGobyPresets(path)
	if err != nil {
		t.Fatal(err)
	}
	if presets["enterprise"] != "21,22,80,U:161" {
		t.Errorf("enterprise = %q", presets["enterprise"])
	}
	if presets["all"] != "0-65535" {
		t.Errorf("scanConfig.All should map to \"all\", got %q", presets["all"])
	}
	if _, err := LoadGobyPresets(path + ".missing"); err == nil {
		t.Error("missing file should fail")
	}
	bad := t.TempDir() + "/bad.json"
	if err := writeFile(bad, "not json"); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadGobyPresets(bad); err == nil {
		t.Error("invalid json should fail")
	}
}

func TestGobyPresetMatchesUpstreamNumbers(t *testing.T) {
	// Goby's own "Minimal" preset, kept byte-identical on purpose.
	spec, _ := LookupPreset("minimal")
	want := "21,22,80,U:137,U:161,443,445,U:1900,3306,3389,U:5353,8080"
	if spec != want {
		t.Errorf("minimal preset = %q, want %q", spec, want)
	}
	if !strings.Contains(spec, "U:161") {
		t.Error("minimal preset should keep Goby's UDP markers")
	}
}
