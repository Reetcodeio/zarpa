// Package fingerprint turns raw keys into salted, irreversible identifiers.
//
// fingerprint = hex(HMAC-SHA256(user_salt, key)). The salt is 32 random
// bytes generated once per user and kept in the OS keychain (macOS
// Keychain via /usr/bin/security; Linux Secret Service via secret-tool).
// When no keychain is reachable it falls back to a 0600 file in the user
// config directory and says so.
package fingerprint

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
)

const (
	keychainService = "zarpa"
	keychainAccount = "fingerprint-salt"
	saltBytes       = 32
)

// Hasher computes fingerprints with one salt.
type Hasher struct {
	salt []byte
	// Where tells the user where the salt lives ("macOS Keychain", a file path, ...).
	Where string
}

// Of returns the fingerprint of a raw key.
func (h *Hasher) Of(key string) string {
	m := hmac.New(sha256.New, h.salt)
	m.Write([]byte(key))
	return hex.EncodeToString(m.Sum(nil))
}

// NewWithSalt builds a hasher from a known salt (tests).
func NewWithSalt(salt []byte, where string) *Hasher {
	return &Hasher{salt: append([]byte(nil), salt...), Where: where}
}

// Open loads the user's salt, creating it on first use.
// saltFile, when non-empty, forces the file store (also set by ZARPA_SALT_FILE).
func Open(saltFile string) (*Hasher, error) {
	if saltFile == "" {
		saltFile = os.Getenv("ZARPA_SALT_FILE")
	}
	if saltFile != "" {
		return fromFile(saltFile)
	}
	if ks := keychainFor(); ks != nil {
		salt, err := ks.get()
		if err == nil {
			return &Hasher{salt: salt, Where: ks.name()}, nil
		}
		if errors.Is(err, errNotFound) {
			salt, err = newSalt()
			if err != nil {
				return nil, err
			}
			if err = ks.set(salt); err == nil {
				return &Hasher{salt: salt, Where: ks.name()}, nil
			}
		}
		// Keychain present but unusable (locked, headless session): fall through.
	}
	dir, err := os.UserConfigDir()
	if err != nil {
		return nil, fmt.Errorf("fingerprint: no keychain and no config dir: %w", err)
	}
	return fromFile(filepath.Join(dir, "zarpa", "salt"))
}

func newSalt() ([]byte, error) {
	b := make([]byte, saltBytes)
	if _, err := rand.Read(b); err != nil {
		return nil, fmt.Errorf("fingerprint: random: %w", err)
	}
	return b, nil
}

func fromFile(path string) (*Hasher, error) {
	if b, err := os.ReadFile(path); err == nil {
		salt, derr := hex.DecodeString(strings.TrimSpace(string(b)))
		if derr != nil || len(salt) != saltBytes {
			return nil, fmt.Errorf("fingerprint: salt file %s is corrupt", path)
		}
		return &Hasher{salt: salt, Where: path}, nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("fingerprint: read salt: %w", err)
	}
	salt, err := newSalt()
	if err != nil {
		return nil, err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, fmt.Errorf("fingerprint: %w", err)
	}
	if err := os.WriteFile(path, []byte(hex.EncodeToString(salt)+"\n"), 0o600); err != nil {
		return nil, fmt.Errorf("fingerprint: write salt: %w", err)
	}
	return &Hasher{salt: salt, Where: path}, nil
}

var errNotFound = errors.New("not found")

type keystore interface {
	name() string
	get() ([]byte, error)
	set(salt []byte) error
}

func keychainFor() keystore {
	switch runtime.GOOS {
	case "darwin":
		if _, err := exec.LookPath("/usr/bin/security"); err == nil {
			return macKeychain{}
		}
	case "linux":
		if p, err := exec.LookPath("secret-tool"); err == nil && os.Getenv("DBUS_SESSION_BUS_ADDRESS") != "" {
			return secretTool{bin: p}
		}
	}
	return nil
}

type macKeychain struct{}

func (macKeychain) name() string { return "macOS Keychain" }

func (macKeychain) get() ([]byte, error) {
	out, err := exec.Command("/usr/bin/security", "find-generic-password",
		"-s", keychainService, "-a", keychainAccount, "-w").Output()
	if err != nil {
		var ee *exec.ExitError
		if errors.As(err, &ee) && ee.ExitCode() == 44 { // errSecItemNotFound
			return nil, errNotFound
		}
		return nil, err
	}
	return decodeSalt(string(out))
}

func (macKeychain) set(salt []byte) error {
	// The salt is not a credential; passing it as an argument is acceptable.
	// Real keys (zarpa vault) are written via stdin instead.
	return exec.Command("/usr/bin/security", "add-generic-password", "-U",
		"-s", keychainService, "-a", keychainAccount,
		"-l", "Zarpa fingerprint salt",
		"-w", hex.EncodeToString(salt)).Run()
}

type secretTool struct{ bin string }

func (secretTool) name() string { return "Secret Service keyring" }

func (s secretTool) get() ([]byte, error) {
	out, err := exec.Command(s.bin, "lookup", "service", keychainService, "account", keychainAccount).Output()
	if err != nil || len(strings.TrimSpace(string(out))) == 0 {
		return nil, errNotFound
	}
	return decodeSalt(string(out))
}

func (s secretTool) set(salt []byte) error {
	cmd := exec.Command(s.bin, "store", "--label=Zarpa fingerprint salt",
		"service", keychainService, "account", keychainAccount)
	cmd.Stdin = strings.NewReader(hex.EncodeToString(salt))
	return cmd.Run()
}

func decodeSalt(s string) ([]byte, error) {
	salt, err := hex.DecodeString(strings.TrimSpace(s))
	if err != nil || len(salt) != saltBytes {
		return nil, errors.New("fingerprint: stored salt is corrupt")
	}
	return salt, nil
}
