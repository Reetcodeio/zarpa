//go:build darwin

package item

import (
	"os"
	"syscall"
)

// sfDataless is SF_DATALESS from <sys/stat.h>: the file's content lives only
// in iCloud (or another file provider). Reading it makes macOS download it,
// which can take minutes, so the scanner skips such files.
const sfDataless = 0x40000000

// IsCloudOnly reports files and folders whose content is not on this Mac.
func IsCloudOnly(fi os.FileInfo) bool {
	st, ok := fi.Sys().(*syscall.Stat_t)
	return ok && st.Flags&sfDataless != 0
}
