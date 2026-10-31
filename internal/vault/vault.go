// Package vault keeps API keys in the OS keychain, named like env vars,
// so `zarpa run` can inject them without a .env file.
//
// macOS: login Keychain via /usr/bin/security. Values are passed through
// stdin in `security -i` mode, never as command-line arguments (which other
// processes can read with ps). Linux: Secret Service via secret-tool, also
// through stdin. There is no plaintext fallback: without a keychain the
// vault refuses to store anything.
package vault

import (
	"bytes"
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"regexp"
	"runtime"
	"sort"
	"strings"
)

const (
	service    = "zarpa-vault"
	indexEntry = "__zarpa_index__" // newline-separated names, base64
)

// ErrNotFound is returned for names not in the vault.
var ErrNotFound = errors.New("not in the vault")

// ErrNoKeychain is returned when no supported keychain is available.
var ErrNoKeychain = errors.New("no supported keychain on this system (macOS Keychain or Linux Secret Service)")

var nameRe = regexp.MustCompile(`^[A-Z_][A-Z0-9_]{0,127}$`)

// ValidName reports whether name can be an env var (OPENAI_API_KEY style).
func ValidName(name string) bool { return nameRe.MatchString(name) }

// backend is the raw keychain: account -> value.
type backend interface {
	set(account, value string) error
	get(account string) (string, error)
	del(account string) error
}

// Vault stores named keys.
type Vault struct{ b backend }

// Open returns the vault for this OS.
func Open() (*Vault, error) {
	switch runtime.GOOS {
	case "darwin":
		return &Vault{b: macKeychain{bin: "/usr/bin/security", service: service}}, nil
	case "linux":
		if p, err := exec.LookPath("secret-tool"); err == nil {
			return &Vault{b: secretTool{bin: p, service: service}}, nil
		}
	}
	return nil, ErrNoKeychain
}

// Secrets is a keychain store for Zarpa's own credentials (the cloud CLI
// token). It is a separate keychain service, so its entries never show up in
// `vault ls` or get injected by `zarpa run`.
type Secrets struct{ b backend }

// OpenSecrets opens the keychain service for Zarpa's own credentials.
func OpenSecrets() (*Secrets, error) {
	const svc = "zarpa-cloud"
	switch runtime.GOOS {
	case "darwin":
		return &Secrets{b: macKeychain{bin: "/usr/bin/security", service: svc}}, nil
	case "linux":
		if p, err := exec.LookPath("secret-tool"); err == nil {
			return &Secrets{b: secretTool{bin: p, service: svc}}, nil
		}
	}
	return nil, ErrNoKeychain
}

// MemorySecrets returns an in-memory store (tests).
func MemorySecrets() *Secrets { return &Secrets{b: memBackend{}} }

var accountRe = regexp.MustCompile(`^[a-z][a-z0-9-]{0,63}$`)

// Set stores value under account and reads it back.
func (s *Secrets) Set(account, value string) error {
	if !accountRe.MatchString(account) || value == "" {
		return errors.New("vault: bad account or empty value")
	}
	if err := s.b.set(account, value); err != nil {
		return err
	}
	if got, err := s.b.get(account); err != nil || got != value {
		return errors.New("vault: the keychain did not store the value (is it locked?)")
	}
	return nil
}

// Get returns the value under account, or ErrNotFound.
func (s *Secrets) Get(account string) (string, error) {
	if !accountRe.MatchString(account) {
		return "", ErrNotFound
	}
	return s.b.get(account)
}

// Delete removes account. Missing is not an error.
func (s *Secrets) Delete(account string) error {
	if err := s.b.del(account); err != nil && !errors.Is(err, ErrNotFound) {
		return err
	}
	return nil
}

// Memory returns an in-memory vault (tests).
func Memory() *Vault { return &Vault{b: memBackend{}} }

// Set stores value under name, replacing any previous value.
func (v *Vault) Set(name, value string) error {
	if !ValidName(name) {
		return fmt.Errorf("vault: %q is not a valid name (use A-Z, 0-9 and _, like OPENAI_API_KEY)", name)
	}
	value = strings.TrimRight(value, "\r\n")
	if value == "" {
		return errors.New("vault: empty value")
	}
	if err := v.b.set(name, value); err != nil {
		return err
	}
	// Read back: a keychain that silently refused must not look like success.
	if got, err := v.b.get(name); err != nil || got != value {
		return errors.New("vault: the keychain did not store the value (is it locked?)")
	}
	names, _ := v.List()
	return v.writeIndex(append(names, name))
}

// Get returns the value stored under name.
func (v *Vault) Get(name string) (string, error) {
	if !ValidName(name) {
		return "", ErrNotFound
	}
	return v.b.get(name)
}

// Delete removes name from the vault.
func (v *Vault) Delete(name string) error {
	if err := v.b.del(name); err != nil {
		return err
	}
	names, _ := v.List()
	keep := names[:0]
	for _, n := range names {
		if n != name {
			keep = append(keep, n)
		}
	}
	return v.writeIndex(keep)
}

// List returns stored names, sorted.
func (v *Vault) List() ([]string, error) {
	raw, err := v.b.get(indexEntry)
	if errors.Is(err, ErrNotFound) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var names []string
	for _, n := range strings.Split(raw, "\n") {
		if ValidName(n) {
			names = append(names, n)
		}
	}
	return names, nil
}

func (v *Vault) writeIndex(names []string) error {
	seen := map[string]bool{}
	var uniq []string
	for _, n := range names {
		if !seen[n] {
			seen[n] = true
			uniq = append(uniq, n)
		}
	}
	sort.Strings(uniq)
	if len(uniq) == 0 {
		err := v.b.del(indexEntry)
		if errors.Is(err, ErrNotFound) {
			return nil
		}
		return err
	}
	return v.b.set(indexEntry, strings.Join(uniq, "\n"))
}

// --- macOS Keychain ---------------------------------------------------------

type macKeychain struct{ bin, service string }

// setCommand is the line fed to `security -i` on stdin. The value is base64
// so no quoting or shell characters can break the command.
func (m macKeychain) setCommand(account, value string) string {
	enc := base64.StdEncoding.EncodeToString([]byte(value))
	return fmt.Sprintf("add-generic-password -U -s %s -a %s -l \"Zarpa: %s\" -w %s\n", m.service, account, account, enc)
}

func (m macKeychain) set(account, value string) error {
	cmd := exec.Command(m.bin, "-i")
	cmd.Stdin = strings.NewReader(m.setCommand(account, value))
	var out bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &out
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("vault: keychain: %v", err)
	}
	return nil
}

func (m macKeychain) get(account string) (string, error) {
	out, err := exec.Command(m.bin, "find-generic-password", "-s", m.service, "-a", account, "-w").Output()
	if err != nil {
		var ee *exec.ExitError
		if errors.As(err, &ee) && ee.ExitCode() == 44 {
			return "", ErrNotFound
		}
		return "", fmt.Errorf("vault: keychain: %v", err)
	}
	b, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(out)))
	if err != nil {
		return "", errors.New("vault: stored value is not in Zarpa's format")
	}
	return string(b), nil
}

func (m macKeychain) del(account string) error {
	err := exec.Command(m.bin, "delete-generic-password", "-s", m.service, "-a", account).Run()
	var ee *exec.ExitError
	if errors.As(err, &ee) && ee.ExitCode() == 44 {
		return ErrNotFound
	}
	return err
}

// --- Linux Secret Service ---------------------------------------------------

type secretTool struct{ bin, service string }

func (s secretTool) set(account, value string) error {
	cmd := exec.Command(s.bin, "store", "--label=Zarpa: "+account, "service", s.service, "account", account)
	cmd.Stdin = strings.NewReader(value)
	return cmd.Run()
}

func (s secretTool) get(account string) (string, error) {
	out, err := exec.Command(s.bin, "lookup", "service", s.service, "account", account).Output()
	if err != nil || len(out) == 0 {
		return "", ErrNotFound
	}
	return string(out), nil
}

func (s secretTool) del(account string) error {
	return exec.Command(s.bin, "clear", "service", s.service, "account", account).Run()
}

// --- memory (tests) ---------------------------------------------------------

type memBackend map[string]string

func (m memBackend) set(a, v string) error { m[a] = v; return nil }
func (m memBackend) get(a string) (string, error) {
	v, ok := m[a]
	if !ok {
		return "", ErrNotFound
	}
	return v, nil
}
func (m memBackend) del(a string) error {
	if _, ok := m[a]; !ok {
		return ErrNotFound
	}
	delete(m, a)
	return nil
}

// Env returns os.Environ() plus the named vault entries (all when names is
// empty). Vault values override variables already set.
func (v *Vault) Env(names []string) ([]string, []string, error) {
	if len(names) == 0 {
		var err error
		if names, err = v.List(); err != nil {
			return nil, nil, err
		}
	}
	add := map[string]string{}
	for _, n := range names {
		val, err := v.Get(n)
		if err != nil {
			return nil, nil, fmt.Errorf("%s: %w", n, err)
		}
		add[n] = val
	}
	var env []string
	for _, kv := range os.Environ() {
		if k, _, ok := strings.Cut(kv, "="); ok {
			if _, override := add[k]; override {
				continue
			}
		}
		env = append(env, kv)
	}
	for _, n := range names {
		env = append(env, n+"="+add[n])
	}
	return env, names, nil
}
