//go:build !unix && !windows

package auth

import (
	"context"
	"fmt"
	"io"
	"os"
)

func terminalPromptReader(context.Context, *os.File) (io.Reader, func() error, error) {
	return nil, nil, fmt.Errorf("interactive login is unsupported on this platform; set DJ_CLIENT_ID and DJ_CLIENT_SECRET")
}
