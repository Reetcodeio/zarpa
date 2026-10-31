// Package gitsrc scans every line ever added in a repository's history.
//
// It shells out to the user's git binary (no third-party Go dependency):
// `git log --all -p -U0` streams each commit's added lines, which are
// grouped per commit and file and handed to the scanner with a line map,
// so a finding points at the exact line in the commit that introduced it.
package gitsrc

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os/exec"
	"path"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/Reetcodeio/zarpa/internal/detect"
	"github.com/Reetcodeio/zarpa/internal/item"
	kfs "github.com/Reetcodeio/zarpa/sources/fs"
)

// Options tune a history scan.
type Options struct {
	MaxFileBytes int // cap of added bytes kept per commit+file
	MaxCommits   int // 0 = all
	// OnCommit, when set, is called for each commit read (progress display).
	OnCommit func()
	// Staged scans only what is staged for the next commit (git diff --cached)
	// instead of history. Used by the pre-commit hook.
	Staged bool
	// SelfEmail is this repo's git user.email; commits by anyone else are
	// marked ByOther (cloned third-party repos). Empty = unknown.
	SelfEmail string
}

// HasAuthor reports whether any commit on any branch was written by email.
func HasAuthor(repoRoot, email string) bool {
	out, err := exec.Command("git", "-C", repoRoot, "log", "--all", "-n", "1", "-i",
		"--fixed-strings", "--author="+email, "--format=%H").Output()
	return err == nil && len(strings.TrimSpace(string(out))) > 0
}

// RepoRoot returns the top folder of the git repository containing dir.
func RepoRoot(dir string) (string, error) {
	out, err := exec.Command("git", "-C", dir, "rev-parse", "--show-toplevel").Output()
	if err != nil {
		return "", err
	}
	return filepath.Clean(strings.TrimSpace(string(out))), nil
}

// UserEmail returns the git user.email that applies inside repoRoot.
func UserEmail(repoRoot string) string {
	out, err := exec.Command("git", "-C", repoRoot, "config", "user.email").Output()
	if err != nil {
		return ""
	}
	return strings.ToLower(strings.TrimSpace(string(out)))
}

// Available reports whether a git binary is on PATH.
func Available() bool {
	_, err := exec.LookPath("git")
	return err == nil
}

var hunkRe = regexp.MustCompile(`^@@ -\d+(?:,\d+)? \+(\d+)(?:,\d+)? @@`)

// Scan streams the history of repoRoot and emits one job per commit+file
// that added lines. It returns the number of commits read.
func Scan(ctx context.Context, repoRoot string, opt Options, emit func(item.Job)) (int, error) {
	if opt.MaxFileBytes <= 0 {
		opt.MaxFileBytes = item.DefaultMaxFile
	}
	args := []string{"-C", repoRoot, "-c", "core.quotePath=false", "log", "--all",
		"--no-color", "--no-ext-diff", "--no-textconv", "--no-renames", "-U0", "-p",
		"--format=%x1e%H %ct %ae"}
	if opt.MaxCommits > 0 {
		args = append(args, "-n", strconv.Itoa(opt.MaxCommits))
	}
	if opt.Staged {
		args = []string{"-C", repoRoot, "-c", "core.quotePath=false", "diff", "--cached",
			"--no-color", "--no-ext-diff", "--no-textconv", "--no-renames", "--diff-filter=AM", "-U0"}
	}
	cmd := exec.CommandContext(ctx, "git", args...)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	out, err := cmd.StdoutPipe()
	if err != nil {
		return 0, err
	}
	if err := cmd.Start(); err != nil {
		return 0, fmt.Errorf("git: %w", err)
	}

	name := filepath.Base(repoRoot)
	var (
		commits  int
		sha      string
		when     time.Time
		file     string
		nextLine int
		buf      []byte
		lineMap  []int
		overflow bool
		inHeader bool // between "diff --git" and the first hunk
		author   string
	)
	flush := func() {
		if file != "" && len(buf) > 0 {
			short := sha
			if len(short) > 7 {
				short = short[:7]
			}
			it := item.Item{
				Kind:        item.KindGit,
				Ref:         "git:" + name + "@" + short + ":" + file,
				Path:        file,
				Content:     buf,
				LineMap:     lineMap,
				Repo:        name,
				Commit:      sha,
				CommitTime:  when,
				ByOther:     opt.SelfEmail != "" && author != "" && author != opt.SelfEmail,
				SkipGeneric: kfs.SkipGenericFor(path.Base(file)),
				TestPath:    detect.IsTestPath(file),
			}
			if opt.Staged {
				it.Kind, it.Ref, it.Commit, it.CommitTime = item.KindStaged, "staged:"+name+":"+file, "", time.Time{}
			}
			emit(item.Job{Template: it})
		}
		buf, lineMap, overflow = nil, nil, false
	}

	r := bufio.NewReaderSize(out, 1<<20)
	for {
		line, rerr := readLine(r)
		if len(line) > 0 || rerr == nil {
			switch {
			case len(line) > 0 && line[0] == 0x1e:
				flush()
				file = ""
				commits++
				if opt.OnCommit != nil {
					opt.OnCommit()
				}
				f := bytes.Fields(line[1:])
				if len(f) >= 1 {
					sha = string(f[0])
				}
				if len(f) >= 2 {
					if ts, perr := strconv.ParseInt(string(f[1]), 10, 64); perr == nil {
						when = time.Unix(ts, 0).UTC()
					}
				}
				author = ""
				if len(f) >= 3 {
					author = strings.ToLower(string(f[2]))
				}
			case bytes.HasPrefix(line, []byte("diff --git ")):
				flush()
				file = ""
				inHeader = true
			case inHeader && bytes.HasPrefix(line, []byte("+++ ")):
				p := string(line[4:])
				switch {
				case p == "/dev/null":
					file = ""
				case len(p) > 2 && p[:2] == "b/":
					file = p[2:]
				default:
					file = p
				}
				if file != "" && (kfs.SkipExt(path.Base(file)) || kfs.SkipPath(file)) {
					file = ""
				}
			case bytes.HasPrefix(line, []byte("@@")):
				inHeader = false
				if m := hunkRe.FindSubmatch(line); m != nil {
					nextLine, _ = strconv.Atoi(string(m[1]))
				}
			case !inHeader && len(line) > 0 && line[0] == '+' && file != "":
				if !overflow {
					if len(buf)+len(line) > opt.MaxFileBytes {
						overflow = true
					} else {
						buf = append(buf, line[1:]...)
						buf = append(buf, '\n')
						lineMap = append(lineMap, nextLine)
					}
				}
				nextLine++
			}
		}
		if rerr != nil {
			if !errors.Is(rerr, io.EOF) {
				_ = cmd.Process.Kill()
				_ = cmd.Wait()
				return commits, rerr
			}
			break
		}
	}
	flush()
	if err := cmd.Wait(); err != nil {
		msg := bytes.TrimSpace(stderr.Bytes())
		if bytes.Contains(msg, []byte("does not have any commits")) {
			return 0, nil
		}
		return commits, fmt.Errorf("git log in %s: %v: %s", repoRoot, err, msg)
	}
	return commits, nil
}

// readLine returns one line without its newline, joining lines longer than
// the reader's buffer.
func readLine(r *bufio.Reader) ([]byte, error) {
	var full []byte
	for {
		chunk, err := r.ReadSlice('\n')
		if errors.Is(err, bufio.ErrBufferFull) {
			full = append(full, chunk...)
			continue
		}
		if full != nil {
			full = append(full, chunk...)
			chunk = full
		} else if len(chunk) > 0 {
			chunk = append([]byte(nil), chunk...)
		}
		chunk = bytes.TrimSuffix(chunk, []byte{'\n'})
		chunk = bytes.TrimSuffix(chunk, []byte{'\r'})
		return chunk, err
	}
}
