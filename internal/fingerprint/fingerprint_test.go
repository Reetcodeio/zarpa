package fingerprint

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestFileSaltIsStableAndPrivate(t *testing.T) {
	p := filepath.Join(t.TempDir(), "zarpa", "salt")
	a, err := Open(p)
	if err != nil {
		t.Fatal(err)
	}
	b, err := Open(p)
	if err != nil {
		t.Fatal(err)
	}
	if a.Of("k") != b.Of("k") {
		t.Fatal("same salt file must give the same fingerprint")
	}
	if len(a.Of("k")) != 64 {
		t.Fatal("fingerprint must be 32 bytes hex")
	}
	fi, _ := os.Stat(p)
	// Windows has no Unix permission bits (files report 0666); the file is
	// in the user's own profile folder there.
	if runtime.GOOS != "windows" && fi.Mode().Perm()&0o077 != 0 {
		t.Fatalf("salt file mode %v is readable by others", fi.Mode().Perm())
	}
	c, _ := Open(filepath.Join(t.TempDir(), "salt"))
	if c.Of("k") == a.Of("k") {
		t.Fatal("different salts must give different fingerprints")
	}
}

func TestCorruptSaltIsAnError(t *testing.T) {
	p := filepath.Join(t.TempDir(), "salt")
	must(t, os.WriteFile(p, []byte("nothex"), 0o600))
	if _, err := Open(p); err == nil {
		t.Fatal("corrupt salt must not be silently replaced")
	}
}
