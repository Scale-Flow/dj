//go:build unix

package auth

import (
	"context"
	"errors"
	"io"
	"os"

	"golang.org/x/sys/unix"
)

type cancellableTerminalReader struct {
	ctx context.Context
	fd  int
}

func terminalPromptReader(ctx context.Context, in *os.File) (io.Reader, func() error, error) {
	fd := int(in.Fd())
	flags, err := unix.FcntlInt(uintptr(fd), unix.F_GETFL, 0)
	if err != nil {
		return nil, nil, err
	}
	if err := unix.SetNonblock(fd, true); err != nil {
		return nil, nil, err
	}
	restore := func() error {
		_, err := unix.FcntlInt(uintptr(fd), unix.F_SETFL, flags)
		return err
	}
	return &cancellableTerminalReader{ctx: ctx, fd: fd}, restore, nil
}

func (r *cancellableTerminalReader) Read(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	for {
		if err := r.ctx.Err(); err != nil {
			return 0, err
		}
		fds := []unix.PollFd{{Fd: int32(r.fd), Events: unix.POLLIN}}
		n, err := unix.Poll(fds, 25)
		if errors.Is(err, unix.EINTR) || n == 0 && err == nil {
			continue
		}
		if err != nil {
			return 0, err
		}
		if err := r.ctx.Err(); err != nil {
			return 0, err
		}
		n, err = unix.Read(r.fd, p[:1])
		if errors.Is(err, unix.EAGAIN) || errors.Is(err, unix.EINTR) {
			continue
		}
		if n == 0 && err == nil {
			return 0, io.EOF
		}
		return n, err
	}
}
