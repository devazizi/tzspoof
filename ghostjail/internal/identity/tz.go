// Package identity resolves and renders the spoofed host identity:
// timezone, hostname, machine-id and the /etc files that expose them.
package identity

import (
	"bytes"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// ZoneinfoDir is the system tz database location.
const ZoneinfoDir = "/usr/share/zoneinfo"

// Zone is a resolved timezone: its canonical name and tzfile path.
type Zone struct {
	Name string // e.g. "Asia/Tokyo"
	Path string // e.g. "/usr/share/zoneinfo/Asia/Tokyo"
}

var aliases = map[string]string{
	"utc": "UTC", "gmt": "GMT", "zulu": "UTC",
	"tokyo": "Asia/Tokyo", "japan": "Asia/Tokyo",
	"london": "Europe/London", "uk": "Europe/London",
	"paris": "Europe/Paris", "berlin": "Europe/Berlin", "germany": "Europe/Berlin",
	"amsterdam": "Europe/Amsterdam", "rome": "Europe/Rome", "madrid": "Europe/Madrid",
	"zurich": "Europe/Zurich", "stockholm": "Europe/Stockholm", "oslo": "Europe/Oslo",
	"helsinki": "Europe/Helsinki", "warsaw": "Europe/Warsaw", "prague": "Europe/Prague",
	"vienna": "Europe/Vienna", "brussels": "Europe/Brussels", "athens": "Europe/Athens",
	"istanbul": "Europe/Istanbul", "moscow": "Europe/Moscow",
	"ny": "America/New_York", "nyc": "America/New_York", "newyork": "America/New_York",
	"new-york": "America/New_York", "la": "America/Los_Angeles",
	"losangeles": "America/Los_Angeles", "los-angeles": "America/Los_Angeles",
	"chicago": "America/Chicago", "denver": "America/Denver", "phoenix": "America/Phoenix",
	"toronto": "America/Toronto", "vancouver": "America/Vancouver", "montreal": "America/Toronto",
	"saopaulo": "America/Sao_Paulo", "sao-paulo": "America/Sao_Paulo",
	"buenosaires": "America/Argentina/Buenos_Aires", "mexicocity": "America/Mexico_City",
	"dubai": "Asia/Dubai", "uae": "Asia/Dubai", "tehran": "Asia/Tehran", "iran": "Asia/Tehran",
	"singapore": "Asia/Singapore", "hongkong": "Asia/Hong_Kong", "hong-kong": "Asia/Hong_Kong",
	"seoul": "Asia/Seoul", "korea": "Asia/Seoul", "shanghai": "Asia/Shanghai",
	"beijing": "Asia/Shanghai", "china": "Asia/Shanghai", "bangkok": "Asia/Bangkok",
	"thailand": "Asia/Bangkok", "jakarta": "Asia/Jakarta", "kualalumpur": "Asia/Kuala_Lumpur",
	"delhi": "Asia/Kolkata", "kolkata": "Asia/Kolkata", "mumbai": "Asia/Kolkata",
	"india": "Asia/Kolkata", "sydney": "Australia/Sydney", "melbourne": "Australia/Melbourne",
	"brisbane": "Australia/Brisbane", "perth": "Australia/Perth", "auckland": "Pacific/Auckland",
	"cairo": "Africa/Cairo", "johannesburg": "Africa/Johannesburg",
}

// isTZif reports whether path is a regular file with the TZif magic header.
func isTZif(path string) bool {
	f, err := os.Open(path)
	if err != nil {
		return false
	}
	defer f.Close()
	if st, err := f.Stat(); err != nil || !st.Mode().IsRegular() {
		return false
	}
	magic := make([]byte, 4)
	n, _ := f.Read(magic)
	return n == 4 && bytes.Equal(magic, []byte("TZif"))
}

// ResolveZone maps an alias, canonical name, absolute tzfile path, or
// unambiguous search term to a zone.
func ResolveZone(input string) (Zone, error) {
	in := strings.TrimSpace(input)
	if in == "" {
		return Zone{}, fmt.Errorf("empty timezone")
	}
	if canon, ok := aliases[strings.ToLower(in)]; ok {
		p := filepath.Join(ZoneinfoDir, canon)
		if isTZif(p) {
			return Zone{Name: canon, Path: p}, nil
		}
	}

	direct := in
	if !filepath.IsAbs(direct) {
		direct = filepath.Join(ZoneinfoDir, in)
	}
	if isTZif(direct) {
		name := strings.TrimPrefix(direct, ZoneinfoDir+"/")
		return Zone{Name: name, Path: direct}, nil
	}

	matches := searchZones(in)
	if len(matches) == 1 {
		return zoneFor(matches[0]), nil
	}
	for _, m := range matches {
		if strings.EqualFold(filepath.Base(m), in) {
			return zoneFor(m), nil
		}
	}
	if len(matches) == 0 {
		return Zone{}, fmt.Errorf("timezone %q not found (see 'ghostjail zones')", in)
	}
	shown := matches
	if len(shown) > 10 {
		shown = shown[:10]
	}
	return Zone{}, fmt.Errorf("timezone %q is ambiguous: %s", in, strings.Join(shown, ", "))
}

func zoneFor(name string) Zone {
	return Zone{Name: name, Path: filepath.Join(ZoneinfoDir, name)}
}

// searchZones returns zone names containing term (case-insensitive).
func searchZones(term string) []string {
	var out []string
	for _, z := range ListZones("") {
		if strings.EqualFold(z, term) {
			return []string{z}
		}
		if strings.Contains(strings.ToLower(z), strings.ToLower(term)) {
			out = append(out, z)
		}
	}
	return out
}

// ListZones returns valid zone names, optionally filtered by substring.
func ListZones(filter string) []string {
	var out []string
	_ = filepath.WalkDir(ZoneinfoDir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		rel := strings.TrimPrefix(path, ZoneinfoDir+"/")
		if d.IsDir() {
			switch rel {
			case "posix", "right", "SystemV":
				return filepath.SkipDir
			}
			return nil
		}
		if rel == "localtime" || rel == "posixrules" || strings.Contains(rel, ".") {
			return nil
		}
		if filter != "" && !strings.Contains(strings.ToLower(rel), strings.ToLower(filter)) {
			return nil
		}
		if isTZif(path) {
			out = append(out, rel)
		}
		return nil
	})
	sort.Strings(out)
	return out
}
