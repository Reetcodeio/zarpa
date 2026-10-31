//go:build darwin || linux

package main

import (
	"os"
	"syscall"
	"unsafe"
)

// termWidth returns the terminal's column count, or 80 if unknown.
func termWidth(f *os.File) int {
	var ws struct{ Row, Col, X, Y uint16 }
	_, _, errno := syscall.Syscall(syscall.SYS_IOCTL, f.Fd(), uintptr(syscall.TIOCGWINSZ), uintptr(unsafe.Pointer(&ws)))
	if errno != 0 || ws.Col == 0 {
		return 80
	}
	return int(ws.Col)
}
