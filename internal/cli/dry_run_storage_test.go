package cli

import (
	"context"
	"strings"
	"testing"

	"github.com/scale-flow/dj/internal/cli/cliutil"
)

func TestEveryAPIPreviewSkipsAllCredentialStores(t *testing.T) {
	commands := [][]string{
		{"search", "--q", "song", "--type", "track"}, {"tracks", "get", "--id", "fake"},
		{"albums", "get", "--id", "fake"}, {"albums", "tracks", "--id", "fake", "--all"},
		{"player", "status"}, {"player", "now-playing"}, {"player", "devices"},
		{"player", "play"}, {"player", "pause"}, {"player", "next"}, {"player", "previous"},
	}
	for _, args := range commands {
		t.Run(strings.Join(args, " "), func(t *testing.T) {
			t.Setenv("XDG_CONFIG_HOME", t.TempDir())
			keyTokens, fileTokens := &backendTokenSpy{}, &backendTokenSpy{}
			keyClients, fileClients := &backendCredentialSpy{}, &backendCredentialSpy{}
			ctx := cliutil.WithAuthStores(context.Background(), cliutil.AuthStores{
				KeychainTokens: keyTokens, FileTokens: fileTokens, KeychainCredentials: keyClients, FileCredentials: fileClients,
			})
			out, err := runBackendCommand(t, ctx, "", append(args, "--dry-run")...)
			if err != nil {
				t.Fatalf("preview failed: %v %s", err, out)
			}
			if *keyTokens != (backendTokenSpy{}) || *fileTokens != (backendTokenSpy{}) || *keyClients != (backendCredentialSpy{}) || *fileClients != (backendCredentialSpy{}) {
				t.Fatal("preview read or mutated credential backend")
			}
		})
	}
}
