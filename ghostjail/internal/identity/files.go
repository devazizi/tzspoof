package identity

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"strings"
)

// MaxHostname is Linux HOST_NAME_MAX.
const MaxHostname = 64

// ValidHostname enforces RFC 1123: dot-separated labels of [A-Za-z0-9-],
// 1-63 chars each, no leading/trailing hyphen, at most 64 chars total.
func ValidHostname(name string) bool {
	if name == "" || len(name) > MaxHostname {
		return false
	}
	for _, label := range strings.Split(name, ".") {
		if label == "" || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, c := range label {
			if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-') {
				return false
			}
		}
	}
	return true
}

// HostsWithName prepends "127.0.1.1 <name>" so forward and reverse lookups
// of the spoofed name resolve locally (first match wins in nss-files).
func HostsWithName(orig, name string) string {
	return fmt.Sprintf("# ghostjail: spoofed hostname\n127.0.1.1\t%s\n%s", name, orig)
}

// NsswitchFilesFirst moves "files" to the front of the hosts: line. Modules
// such as "resolve" (systemd-resolved) answer from outside the namespace
// and would otherwise return the real host's data before /etc/hosts is read.
func NsswitchFilesFirst(orig string) string {
	lines := strings.Split(orig, "\n")
	for i, line := range lines {
		trimmed := strings.TrimLeft(line, " \t")
		if !strings.HasPrefix(trimmed, "hosts:") {
			continue
		}
		out := []string{"hosts:", "files"}
		skipAction := false
		for _, tok := range strings.Fields(strings.TrimPrefix(trimmed, "hosts:")) {
			if tok == "files" {
				skipAction = true
				continue
			}
			if skipAction && strings.HasPrefix(tok, "[") {
				continue // action bound to the old "files" entry
			}
			skipAction = false
			out = append(out, tok)
		}
		lines[i] = strings.Join(out, " ")
	}
	return strings.Join(lines, "\n")
}

// RandomMachineID returns a systemd-style machine-id (32 lowercase hex).
func RandomMachineID() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	// Mark as RFC 4122 v4 like systemd-machine-id-setup does.
	b[6] = b[6]&0x0f | 0x40
	b[8] = b[8]&0x3f | 0x80
	return hex.EncodeToString(b), nil
}

// ValidMachineID reports whether id is 32 lowercase hex characters.
func ValidMachineID(id string) bool {
	if len(id) != 32 {
		return false
	}
	_, err := hex.DecodeString(id)
	return err == nil && strings.ToLower(id) == id
}
