package item

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestChunkedReadNeverSplitsLines(t *testing.T) {
	var b strings.Builder
	for i := 0; i < 5000; i++ {
		b.WriteString("line-")
		b.WriteString(strings.Repeat("x", i%300))
		b.WriteString("-end\n")
	}
	p := filepath.Join(t.TempDir(), "big.jsonl")
	must(t, os.WriteFile(p, []byte(b.String()), 0o600))

	var got bytes.Buffer
	lines := 0
	_, err := ReadFile(p, ReadOptions{MaxWhole: 1024, Chunked: true, ChunkSize: 4096}, func(c []byte, off int) {
		if off != lines {
			t.Fatalf("line offset %d, want %d", off, lines)
		}
		if !bytes.HasSuffix(c, []byte("-end\n")) {
			t.Fatalf("chunk does not end on a line boundary")
		}
		lines += bytes.Count(c, []byte{'\n'})
		got.Write(c)
	})
	if err != nil {
		t.Fatal(err)
	}
	if got.String() != b.String() {
		t.Fatal("chunks do not reassemble to the file")
	}
}

func TestBinaryAndTooLarge(t *testing.T) {
	dir := t.TempDir()
	bin := filepath.Join(dir, "b")
	must(t, os.WriteFile(bin, []byte("abc\x00def"), 0o600))
	if _, err := ReadFile(bin, ReadOptions{MaxWhole: 100}, func([]byte, int) {}); err != ErrBinary {
		t.Fatalf("want ErrBinary, got %v", err)
	}
	big := filepath.Join(dir, "big")
	must(t, os.WriteFile(big, bytes.Repeat([]byte("a"), 200), 0o600))
	_, err := ReadFile(big, ReadOptions{MaxWhole: 100}, func([]byte, int) {})
	if _, ok := err.(*TooLargeError); !ok {
		t.Fatalf("want TooLargeError, got %v", err)
	}
}
