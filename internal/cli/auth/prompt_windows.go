//go:build windows

package auth

import (
	"context"
	"encoding/binary"
	"io"
	"os"
	"unicode/utf16"
	"unsafe"

	"golang.org/x/sys/windows"
)

var readConsoleInput = windows.NewLazySystemDLL("kernel32.dll").NewProc("ReadConsoleInputW")

type consoleInputRecord struct {
	eventType uint16
	_         uint16
	data      [16]byte
}

type cancellableTerminalReader struct {
	ctx     context.Context
	handle  windows.Handle
	pending []byte
	high    uint16
}

func terminalPromptReader(ctx context.Context, in *os.File) (io.Reader, func() error, error) {
	return &cancellableTerminalReader{ctx: ctx, handle: windows.Handle(in.Fd())}, func() error { return nil }, nil
}

func (r *cancellableTerminalReader) Read(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	for {
		if err := r.ctx.Err(); err != nil {
			return 0, err
		}
		if len(r.pending) > 0 {
			n := copy(p, r.pending)
			r.pending = r.pending[n:]
			return n, nil
		}
		ready, err := windows.WaitForSingleObject(r.handle, 25)
		if err != nil {
			return 0, err
		}
		if ready == uint32(windows.WAIT_TIMEOUT) {
			continue
		}
		var record consoleInputRecord
		var count uint32
		ok, _, err := readConsoleInput.Call(uintptr(r.handle), uintptr(unsafe.Pointer(&record)), 1, uintptr(unsafe.Pointer(&count)))
		if ok == 0 {
			return 0, err
		}
		if count == 0 || record.eventType != 1 || binary.LittleEndian.Uint32(record.data[:4]) == 0 {
			continue
		}
		ch := binary.LittleEndian.Uint16(record.data[10:12])
		if ch == 0 {
			continue
		}
		if ch >= 0xd800 && ch <= 0xdbff {
			r.high = ch
			continue
		}
		value := rune(ch)
		if r.high != 0 {
			value = utf16.DecodeRune(rune(r.high), value)
			r.high = 0
		}
		r.pending = []byte(string(value))
	}
}
