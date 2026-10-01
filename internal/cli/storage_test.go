package cli

import (
	"context"
	"encoding/json"
	"github.com/scale-flow/dj/internal/cli/cliutil"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Scale-Flow/marten/pkg/oauth"
)

func TestAPIExplicitFileStorageAndDeviceEnvelope(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", dir)
	store := oauth.NewOAuthStore(filepath.Join(dir, "dj", "oauth-tokens.json"))
	if err := store.Save("default", oauth.TokenSet{AccessToken: "mock-token", ExpiresAt: time.Now().Add(time.Hour)}); err != nil {
		t.Fatal(err)
	}
	calls := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		if r.Header.Get("Authorization") != "Bearer mock-token" {
			t.Error("wrong auth")
		}
		io.WriteString(w, `{"devices":[{"id":"mock-device","name":"Mock speaker","is_active":true}]}`)
	}))
	defer server.Close()
	root := NewRootCmd("test")
	root.SetContext(context.Background())
	root.SetErr(io.Discard)
	root.SetArgs([]string{"--auth-storage", "file", "--base-url", server.URL, "player", "devices"})
	old := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w
	defer func() { os.Stdout = old; r.Close() }()
	err := root.Execute()
	w.Close()
	output, _ := io.ReadAll(r)
	if err != nil {
		t.Fatal(err)
	}
	if calls != 1 {
		t.Fatal("API not called")
	}
	if !strings.Contains(string(output), `"devices":[{"id":"mock-device"`) {
		t.Fatalf("device envelope lost: %s", output)
	}
}
func TestSpotifyDefaultEndpoint(t *testing.T) {
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	t.Setenv("DJ_BASE_URL", "")
	cmd := NewRootCmd("test")
	cmd.Flags().AddFlagSet(cmd.PersistentFlags())
	ctx, err := cliutil.ResolveSpotifyContext(cmd)
	if err != nil || ctx.BaseURL != "https://api.spotify.com" {
		t.Fatal("missing Spotify default")
	}
	cmd.Flags().Set("base-url", "https://example.test")
	ctx, err = cliutil.ResolveSpotifyContext(cmd)
	if err != nil || ctx.BaseURL != "https://example.test" {
		t.Fatal("explicit endpoint overridden")
	}
}

func TestTrackPlaybackUsesJSONArray(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", dir)
	store := oauth.NewOAuthStore(filepath.Join(dir, "dj", "oauth-tokens.json"))
	if err := store.Save("default", oauth.TokenSet{AccessToken: "mock-token", ExpiresAt: time.Now().Add(time.Hour)}); err != nil {
		t.Fatal(err)
	}
	calls := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		if r.Method != "PUT" || r.URL.Query().Get("device_id") != "mock-device" {
			t.Error("wrong playback target")
		}
		var body struct {
			URIs []string `json:"uris"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Error(err)
		}
		if len(body.URIs) != 2 || body.URIs[0] != "spotify:track:one" || body.URIs[1] != "spotify:track:two" {
			t.Error("wrong track array")
		}
		w.WriteHeader(204)
	}))
	defer server.Close()
	cmd := NewRootCmd("test")
	cmd.SetArgs([]string{"--auth-storage", "file", "--base-url", server.URL, "player", "play", "--device-id", "mock-device", "--uris", "spotify:track:one,spotify:track:two", "--yes"})
	if err := cmd.Execute(); err != nil {
		t.Fatal(err)
	}
	if calls != 1 {
		t.Fatal("play not called")
	}
}
