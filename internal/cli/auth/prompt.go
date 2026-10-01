package auth

import (
	"context"
	"fmt"
	"io"
	"os"
	"strings"
	"unicode/utf8"

	"github.com/Scale-Flow/marten/pkg/cmdutil"
	"github.com/spf13/cobra"
	"golang.org/x/term"
)

func resolveEnvOrPrompt(cmd *cobra.Command, envVar, prompt string, hidden, required bool) (string, error) {
	if err := cmd.Context().Err(); err != nil {
		return "", err
	}
	if value := os.Getenv(envVar); value != "" {
		return value, nil
	}
	in, ok := cmd.InOrStdin().(*os.File)
	if !ok || !cmdutil.IsInteractiveInput(in) {
		if required {
			return "", fmt.Errorf("%s not set; set %s or run interactively", envVar, envVar)
		}
		return "", nil
	}
	value, err := readTerminalPrompt(cmd.Context(), in, cmd.ErrOrStderr(), prompt+": ", hidden)
	if err != nil {
		return "", err
	}
	if required && value == "" {
		return "", fmt.Errorf("%s cannot be empty", strings.ToLower(prompt))
	}
	return value, nil
}

func confirmCredentialUpdate(ctx context.Context, in *os.File, out io.Writer) (bool, error) {
	value, err := readTerminalPrompt(ctx, in, out, "Stored credentials found. Update? [y/N]: ", false)
	return strings.EqualFold(value, "y"), err
}

// readTerminalPrompt owns terminal mode for the entire read. The input reader
// checks cancellation without leaving a blocked read goroutine behind, and both
// descriptor flags and terminal mode are restored before the command returns.
func readTerminalPrompt(ctx context.Context, in *os.File, out io.Writer, prompt string, hidden bool) (value string, err error) {
	if err := ctx.Err(); err != nil {
		return "", err
	}
	fd := int(in.Fd())
	state, err := term.MakeRaw(fd)
	if err != nil {
		return "", fmt.Errorf("prepare terminal input: %w", err)
	}
	defer func() {
		if restoreErr := term.Restore(fd, state); restoreErr != nil && err == nil {
			err = fmt.Errorf("restore terminal input: %w", restoreErr)
		}
	}()
	reader, restore, err := terminalPromptReader(ctx, in)
	if err != nil {
		return "", err
	}
	defer func() {
		if restoreErr := restore(); restoreErr != nil && err == nil {
			err = fmt.Errorf("restore terminal descriptor: %w", restoreErr)
		}
	}()
	if _, err := fmt.Fprint(out, prompt); err != nil {
		return "", err
	}
	defer func() { _, _ = fmt.Fprint(out, "\r\n") }()
	line := make([]byte, 0, 128)
	defer func() { clear(line) }()
	var next [1]byte
	for {
		if _, err := io.ReadFull(reader, next[:]); err != nil {
			return "", err
		}
		switch next[0] {
		case '\r', '\n':
			return strings.TrimSpace(string(line)), nil
		case 3: // Ctrl+C in raw mode does not generate an OS signal.
			return "", context.Canceled
		case 4: // Ctrl+D
			if len(line) == 0 {
				return "", io.EOF
			}
			return strings.TrimSpace(string(line)), nil
		case 8, 127:
			if len(line) > 0 {
				_, size := utf8.DecodeLastRune(line)
				clear(line[len(line)-size:])
				line = line[:len(line)-size]
				if !hidden {
					_, _ = fmt.Fprint(out, "\b \b")
				}
			}
		default:
			if next[0] < 32 {
				continue
			}
			if len(line) >= 64*1024 {
				return "", fmt.Errorf("input exceeds 64 KiB")
			}
			line = append(line, next[0])
			if !hidden {
				if _, err := out.Write(next[:]); err != nil {
					return "", err
				}
			}
		}
	}
}
