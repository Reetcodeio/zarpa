//go:build !darwin && !linux

package main

import "os"

func termWidth(f *os.File) int { return 80 }
