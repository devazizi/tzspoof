package identity

import (
	"strings"
	"testing"
)

func TestResolveZone(t *testing.T) {
	cases := map[string]string{
		"tokyo":                     "Asia/Tokyo",
		"TOKYO":                     "Asia/Tokyo",
		"Europe/London":             "Europe/London",
		"  utc ":                    "UTC",
		"Kolkata":                   "Asia/Kolkata",
		ZoneinfoDir + "/Asia/Seoul": "Asia/Seoul",
	}
	for in, want := range cases {
		z, err := ResolveZone(in)
		if err != nil {
			t.Fatalf("ResolveZone(%q): %v", in, err)
		}
		if z.Name != want || z.Path != ZoneinfoDir+"/"+want {
			t.Errorf("ResolveZone(%q) = %+v, want %s", in, z, want)
		}
	}
	for _, bad := range []string{"", "nowhere-zone", "/etc/passwd", "America"} {
		if _, err := ResolveZone(bad); err == nil {
			t.Errorf("ResolveZone(%q) succeeded, want error", bad)
		}
	}
}

func TestValidHostname(t *testing.T) {
	for _, ok := range []string{"a", "build-01", "box.example.com", strings.Repeat("a", 63)} {
		if !ValidHostname(ok) {
			t.Errorf("ValidHostname(%q) = false", ok)
		}
	}
	for _, bad := range []string{"", "-a", "a-", "a..b", ".a", "a.", "sp ace", "a_b", strings.Repeat("a", 64), strings.Repeat("a.", 33) + "a"} {
		if ValidHostname(bad) {
			t.Errorf("ValidHostname(%q) = true", bad)
		}
	}
}

func TestNsswitchFilesFirst(t *testing.T) {
	in := "passwd: files\nhosts: mymachines resolve [!UNAVAIL=return] files myhostname dns\n"
	want := "passwd: files\nhosts: files mymachines resolve [!UNAVAIL=return] myhostname dns\n"
	if got := NsswitchFilesFirst(in); got != want {
		t.Errorf("got %q\nwant %q", got, want)
	}
	// An action bound to "files" moves away with it.
	if got := NsswitchFilesFirst("hosts: dns files [NOTFOUND=return] myhostname"); got != "hosts: files dns myhostname" {
		t.Errorf("got %q", got)
	}
	if got := NsswitchFilesFirst("hosts: dns"); got != "hosts: files dns" {
		t.Errorf("got %q", got)
	}
}

func TestHostsWithName(t *testing.T) {
	got := HostsWithName("127.0.0.1 localhost\n", "box")
	if !strings.HasPrefix(got, "# ghostjail: spoofed hostname\n127.0.1.1\tbox\n127.0.0.1 localhost\n") {
		t.Errorf("got %q", got)
	}
}

func TestMachineID(t *testing.T) {
	id, err := RandomMachineID()
	if err != nil || !ValidMachineID(id) {
		t.Fatalf("RandomMachineID() = %q, %v", id, err)
	}
	if ValidMachineID("ABCDEF0123456789abcdef0123456789") || ValidMachineID("abc") {
		t.Error("ValidMachineID accepted invalid id")
	}
}
