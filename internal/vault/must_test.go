package vault

import "testing"

// must stops the test when a setup step fails (keeps errcheck quiet, and failures visible).
func must(t testing.TB, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}
