//go:build !darwin

package item

import "os"

// IsCloudOnly reports files whose content is not stored locally (macOS only).
func IsCloudOnly(fi os.FileInfo) bool { return false }
