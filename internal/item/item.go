// Package item defines the unit of work that sources hand to the scanner,
// plus a shared, memory-bounded file reader.
package item

import (
	"bufio"
	"bytes"
	"errors"
	"io"
	"os"
	"time"
)

// Location kinds. They mirror key_locations.kind in the control-plane schema.
const (
	KindFile       = "file"
	KindGit        = "git"
	KindMCP        = "mcp"
	KindTranscript = "transcript"
	KindShell      = "shell"
	KindDotfile    = "dotfile"
	KindBundle     = "bundle"
	KindStaged     = "staged" // staged for the next commit (pre-commit hook)
)

// Item is one buffer to scan and the facts needed to describe where it came from.
type Item struct {
	Kind string
	// Ref is the location prefix without the line, for example
	// "repo:web:.env.local", "git:web@3f2c1a9:config.js" or "mcp:cursor:~/.cursor/mcp.json".
	Ref string
	// Path is the OS path for files, or the repo-relative path for git items.
	Path    string
	Content []byte
	// LineOffset is added to match line numbers (chunked reads of big files).
	LineOffset int
	// LineMap, when set, maps buffer line i (0-based) to the real line number.
	LineMap []int

	Repo       string
	Commit     string
	CommitTime time.Time
	ModTime    time.Time
	GitIgnored bool
	Tool       string
	// SkipGeneric turns off the entropy rule (lockfiles, minified vendor code).
	SkipGeneric bool
	// TestPath marks tests, fixtures, docs and examples.
	TestPath bool
	// Machine marks files from machine sources (AI tools, shell, dotfiles).
	Machine bool
	// ByOther marks git items whose commit author is not this repo's user.
	ByOther bool
	// Public marks content that ships to browsers (built bundles).
	Public bool
}

// RealLine converts a 1-based buffer line into the line reported to the user.
func (it *Item) RealLine(bufLine int) int {
	if it.LineMap != nil {
		if bufLine-1 >= 0 && bufLine-1 < len(it.LineMap) {
			return it.LineMap[bufLine-1]
		}
		return 0
	}
	return it.LineOffset + bufLine
}

// ErrBinary is returned for files that look binary.
var ErrBinary = errors.New("binary file")

// ErrCloudOnly is returned for iCloud files not downloaded to this Mac.
var ErrCloudOnly = errors.New("cloud-only file")

// ReadOptions bound how a file is read.
type ReadOptions struct {
	// MaxWhole is the largest file read in one piece. Bigger files are
	// skipped unless Chunked is set.
	MaxWhole int64
	// Chunked streams big files in ChunkSize pieces cut at line boundaries.
	Chunked   bool
	ChunkSize int
	// MaxTotal caps how much of a chunked file is read (0 = no cap).
	MaxTotal int64
}

// ReadFile reads path and calls fn for each piece with the number of lines
// that came before it. It returns ErrBinary for binary content and a
// *TooLargeError when the file exceeds MaxWhole and Chunked is false.
func ReadFile(path string, opt ReadOptions, fn func(content []byte, lineOffset int)) (int64, error) {
	if fi, err := os.Lstat(path); err == nil && IsCloudOnly(fi) {
		return 0, ErrCloudOnly
	}
	f, err := os.Open(path)
	if err != nil {
		return 0, err
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		return 0, err
	}
	size := st.Size()
	if size == 0 {
		return 0, nil
	}
	if size <= opt.MaxWhole {
		b, err := io.ReadAll(f)
		if err != nil {
			return 0, err
		}
		if looksBinary(b) {
			return 0, ErrBinary
		}
		fn(b, 0)
		return int64(len(b)), nil
	}
	if !opt.Chunked {
		return 0, &TooLargeError{Size: size}
	}
	chunk := opt.ChunkSize
	if chunk <= 0 {
		chunk = 4 << 20
	}
	r := bufio.NewReaderSize(f, 1<<20)
	var (
		read    int64
		lines   int
		buf     = make([]byte, 0, chunk+64*1024)
		checked bool
	)
	flush := func() {
		if len(buf) == 0 {
			return
		}
		fn(buf, lines)
		lines += bytes.Count(buf, []byte{'\n'})
		buf = make([]byte, 0, chunk+64*1024)
	}
	for {
		line, err := r.ReadSlice('\n')
		if len(line) > 0 {
			if !checked {
				checked = true
				if looksBinary(line) {
					return 0, ErrBinary
				}
			}
			buf = append(buf, line...)
			read += int64(len(line))
			// Cut only at a line end so a key is never split across chunks.
			if len(buf) >= chunk && err == nil {
				flush()
			}
		}
		if opt.MaxTotal > 0 && read >= opt.MaxTotal {
			break
		}
		if errors.Is(err, bufio.ErrBufferFull) {
			continue // very long line: keep appending
		}
		if err != nil {
			if err == io.EOF {
				break
			}
			return read, err
		}
	}
	flush()
	return read, nil
}

// TooLargeError reports a file skipped for size.
type TooLargeError struct{ Size int64 }

func (e *TooLargeError) Error() string { return "file too large" }

func looksBinary(b []byte) bool {
	n := len(b)
	if n > 8000 {
		n = 8000
	}
	return bytes.IndexByte(b[:n], 0) >= 0
}
