//go:build linux

package auth

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"os"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Scale-Flow/marten/pkg/oauth"
	"golang.org/x/sys/unix"
	"golang.org/x/term"
)

func safetyPTY(t *testing.T) (*os.File, *os.File) {
	t.Helper()
	master, err := os.OpenFile("/dev/ptmx", os.O_RDWR|unix.O_NOCTTY, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { master.Close() })
	if err := unix.IoctlSetPointerInt(int(master.Fd()), unix.TIOCSPTLCK, 0); err != nil {
		t.Fatal(err)
	}
	number, err := unix.IoctlGetInt(int(master.Fd()), unix.TIOCGPTN)
	if err != nil {
		t.Fatal(err)
	}
	slave, err := os.OpenFile(fmt.Sprintf("/dev/pts/%d", number), os.O_RDWR|unix.O_NOCTTY, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { slave.Close() })
	return master, slave
}

type safetyPromptOutput struct {
	mu      sync.Mutex
	buffer  bytes.Buffer
	changed chan struct{}
}

func newSafetyPromptOutput() *safetyPromptOutput {
	return &safetyPromptOutput{changed: make(chan struct{}, 1)}
}

func (w *safetyPromptOutput) Write(p []byte) (int, error) {
	w.mu.Lock()
	n, err := w.buffer.Write(p)
	w.mu.Unlock()
	select {
	case w.changed <- struct{}{}:
	default:
	}
	return n, err
}

func (w *safetyPromptOutput) String() string {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.buffer.String()
}

func (w *safetyPromptOutput) wait(t *testing.T, prompt string) {
	t.Helper()
	deadline := time.NewTimer(2 * time.Second)
	defer deadline.Stop()
	for !strings.Contains(w.String(), prompt) {
		select {
		case <-w.changed:
		case <-deadline.C:
			t.Fatalf("did not reach %q; output: %q", prompt, w.String())
		}
	}
}

// These tests execute the real auth command using a PTY. Cancellation occurs
// while each credential prompt is blocked, rather than in an OAuth mock alone.
func TestLoginCredentialPromptsHonorDeadlineAndCancellation(t *testing.T) {
	for _, stage := range []string{"client ID", "client secret", "stored confirmation"} {
		for _, ending := range []string{"deadline", "context cancellation", "Ctrl+C", "interrupt signal"} {
			t.Run(stage+"/"+ending, func(t *testing.T) {
				t.Setenv("XDG_CONFIG_HOME", t.TempDir())
				t.Setenv("DJ_CLIENT_ID", "")
				t.Setenv("DJ_CLIENT_SECRET", "")
				if stage == "stored confirmation" {
					path, err := oauthStorePath()
					if err != nil {
						t.Fatal(err)
					}
					if err := oauth.NewClientCredentialFileStore(oauth.ClientCredentialPathForTokenStore(path)).Save("test", oauth.ClientCredentials{ClientID: "mock-client"}); err != nil {
						t.Fatal(err)
					}
				}
				master, slave := safetyPTY(t)
				before, err := term.GetState(int(slave.Fd()))
				if err != nil {
					t.Fatal(err)
				}
				beforeFlags, err := unix.FcntlInt(slave.Fd(), unix.F_GETFL, 0)
				if err != nil {
					t.Fatal(err)
				}
				ctx, cancel := context.WithCancel(context.Background())
				defer cancel()
				timeout := "5s"
				if ending == "deadline" {
					timeout = "250ms"
				}
				stderr := newSafetyPromptOutput()
				cmd := safetyAuthCommand(ctx, slave, stderr, "auth", "login", "--auth-storage", "file", "--timeout", timeout)
				type result struct {
					out string
					err error
				}
				done := make(chan result, 1)
				go func() {
					out, err := captureSafetyCommand(t, cmd)
					done <- result{out, err}
				}()
				prompt := "Client ID: "
				if stage == "stored confirmation" {
					prompt = "Stored credentials found. Update?"
				}
				stderr.wait(t, prompt)
				if stage == "client secret" {
					if _, err := io.WriteString(master, "mock-client\n"); err != nil {
						t.Fatal(err)
					}
					stderr.wait(t, "Client Secret: ")
					if _, err := io.WriteString(master, "mock-hidden-secret"); err != nil {
						t.Fatal(err)
					}
				}
				started := time.Now()
				switch ending {
				case "context cancellation":
					cancel()
				case "interrupt signal":
					process, err := os.FindProcess(os.Getpid())
					if err != nil {
						t.Fatal(err)
					}
					if err := process.Signal(os.Interrupt); err != nil {
						t.Fatal(err)
					}
				case "Ctrl+C":
					if _, err := master.Write([]byte{3}); err != nil {
						t.Fatal(err)
					}
				}
				select {
				case result := <-done:
					if result.err == nil || !strings.Contains(result.out, "login timed out or was cancelled") {
						t.Fatalf("unexpected command result: %v; %s", result.err, result.out)
					}
				case <-time.After(time.Second):
					cancel()
					t.Fatal("credential prompt did not stop")
				}
				if time.Since(started) > time.Second {
					t.Fatal("cancellation was not prompt")
				}
				after, err := term.GetState(int(slave.Fd()))
				if err != nil || !reflect.DeepEqual(before, after) {
					t.Fatalf("terminal mode was not restored: %v", err)
				}
				afterFlags, err := unix.FcntlInt(slave.Fd(), unix.F_GETFL, 0)
				if err != nil || beforeFlags != afterFlags {
					t.Fatalf("terminal descriptor flags were not restored: %v; %x -> %x", err, beforeFlags, afterFlags)
				}
				if strings.Contains(stderr.String(), "mock-hidden-secret") || strings.Contains(stderr.String(), "Open this URL") {
					t.Fatalf("secret echoed or login continued after cancellation: %q", stderr.String())
				}
			})
		}
	}
}

func TestManualLoginRelayFailureRestoresTerminal(t *testing.T) {
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	t.Setenv("DJ_CLIENT_ID", "mock-client")
	t.Setenv("DJ_CLIENT_SECRET", "")
	_, slave := safetyPTY(t)
	before, err := term.GetState(int(slave.Fd()))
	if err != nil {
		t.Fatal(err)
	}
	stderr := newSafetyPromptOutput()
	release := make(chan struct{})
	previous := pollForAuthCode
	t.Cleanup(func() { pollForAuthCode = previous })
	pollForAuthCode = func(ctx context.Context, _, _ string, _, _ time.Duration) (string, error) {
		select {
		case <-release:
			return "", fmt.Errorf("mock relay failure")
		case <-ctx.Done():
			return "", ctx.Err()
		}
	}
	cmd := safetyAuthCommand(context.Background(), slave, stderr, "auth", "login", "--timeout", "5s")
	done := make(chan error, 1)
	go func() {
		_, err := captureSafetyCommand(t, cmd)
		done <- err
	}()
	stderr.wait(t, "Paste the authorization code: ")
	close(release)
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("relay failure ignored")
		}
	case <-time.After(time.Second):
		t.Fatal("paste prompt blocked relay failure")
	}
	after, err := term.GetState(int(slave.Fd()))
	if err != nil || !reflect.DeepEqual(before, after) {
		t.Fatalf("paste terminal mode was not restored: %v", err)
	}
}
