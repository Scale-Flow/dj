package cli

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/Scale-Flow/marten/pkg/oauth"
)

func runCommand(t *testing.T, args ...string) (int, map[string]any) {
	t.Helper()
	root := NewRootCmd("test")
	root.SetArgs(args)
	root.SetIn(strings.NewReader("n\n"))
	root.SetErr(io.Discard)
	old := os.Stdout
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	os.Stdout = w
	defer func() { os.Stdout = old; r.Close() }()
	code := Execute(root)
	w.Close()
	output, err := io.ReadAll(r)
	if err != nil {
		t.Fatal(err)
	}
	var envelope map[string]any
	if err := json.Unmarshal(output, &envelope); err != nil {
		t.Fatalf("invalid command JSON %q: %v", output, err)
	}
	return code, envelope
}

func TestProcessUsageErrors(t *testing.T) {
	binary := filepath.Join(t.TempDir(), "dj")
	build := exec.Command("go", "build", "-o", binary, "../../cmd/dj")
	if output, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build: %v %s", err, output)
	}
	cases := [][]string{
		{"search", "--q", "hi"}, {"definitely-not-a-command"}, {"player", "definitely-not-a-command"}, {"--unknown-flag"},
		{"tracks", "get"}, {"player", "play", "unexpected"}, {"player", "play", "--position-ms", "bad"},
		{"--auth-storage", "bad", "player", "devices"},
	}
	for _, args := range cases {
		t.Run(strings.Join(args, " "), func(t *testing.T) {
			cmd := exec.Command(binary, args...)
			cmd.Env = append(os.Environ(), "XDG_CONFIG_HOME="+t.TempDir())
			var stderr bytes.Buffer
			cmd.Stderr = &stderr
			output, err := cmd.Output()
			exit, ok := err.(*exec.ExitError)
			if !ok || exit.ExitCode() != 2 {
				t.Fatalf("exit=%v output=%q stderr=%q", err, output, stderr.String())
			}
			var envelope struct {
				OK    bool `json:"ok"`
				Error struct {
					Code    string `json:"code"`
					Message string `json:"message"`
				} `json:"error"`
			}
			if err := json.Unmarshal(output, &envelope); err != nil {
				t.Fatal(err)
			}
			if envelope.OK || envelope.Error.Code != "validation_error" || envelope.Error.Message == "" {
				t.Fatalf("wrong error: %s", output)
			}
		})
	}
}

func TestDryRunMatchesRequestWithoutCredentialAccess(t *testing.T) {
	cases := []struct {
		name         string
		args         []string
		method, path string
		body         any
	}{
		{"search", []string{"search", "--q", "space & time", "--type", "track,album", "--market", "GB", "--limit", "7", "--offset", "14"}, "GET", "/v1/search?limit=7&market=GB&offset=14&q=space+%26+time&type=track%2Calbum", nil},
		{"track", []string{"tracks", "get", "--id", "track1", "--market", "GB"}, "GET", "/v1/tracks/track1?market=GB", nil},
		{"album", []string{"albums", "get", "--id", "album1", "--market", "GB"}, "GET", "/v1/albums/album1?market=GB", nil},
		{"album_tracks", []string{"albums", "tracks", "--id", "album1", "--market", "GB", "--page", "2", "--per-page", "2"}, "GET", "/v1/albums/album1/tracks?limit=2&market=GB&offset=2", nil},
		{"status", []string{"player", "status", "--market", "GB"}, "GET", "/v1/me/player?market=GB", nil},
		{"now_playing", []string{"player", "now-playing", "--market", "GB"}, "GET", "/v1/me/player/currently-playing?market=GB", nil},
		{"devices", []string{"player", "devices"}, "GET", "/v1/me/player/devices", nil},
		{"play", []string{"player", "play", "--device-id", "speaker & 1", "--uris", "spotify:track:a,spotify:track:b", "--position-ms", "1200"}, "PUT", "/v1/me/player/play?device_id=speaker+%26+1", map[string]any{"uris": []any{"spotify:track:a", "spotify:track:b"}, "position_ms": float64(1200)}},
		{"pause", []string{"player", "pause", "--device-id", "speaker & 1"}, "PUT", "/v1/me/player/pause?device_id=speaker+%26+1", map[string]any{}},
		{"next", []string{"player", "next", "--device-id", "speaker & 1"}, "POST", "/v1/me/player/next?device_id=speaker+%26+1", map[string]any{}},
		{"previous", []string{"player", "previous", "--device-id", "speaker & 1"}, "POST", "/v1/me/player/previous?device_id=speaker+%26+1", map[string]any{}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			t.Setenv("XDG_CONFIG_HOME", dir)
			t.Setenv("DJ_PROFILE", "")
			t.Setenv("DJ_BASE_URL", "")
			calls := 0
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				calls++
				if r.Method != tc.method || r.URL.RequestURI() != tc.path {
					t.Errorf("request %s %s; want %s %s", r.Method, r.URL.RequestURI(), tc.method, tc.path)
				}
				var body any
				if r.Body != nil {
					data, _ := io.ReadAll(r.Body)
					if len(data) > 0 {
						if err := json.Unmarshal(data, &body); err != nil {
							t.Error(err)
						}
					}
				}
				if !reflect.DeepEqual(body, tc.body) {
					t.Errorf("body=%#v want=%#v", body, tc.body)
				}
				if strings.Contains(tc.path, "/tracks?limit=") {
					io.WriteString(w, `{"items":[],"offset":2,"limit":2,"total":2,"next":null}`)
				} else {
					io.WriteString(w, `{}`)
				}
			}))
			defer server.Close()
			prefix := []string{"--base-url", server.URL, "--auth-storage", "file"}
			// A malformed token store catches accidental reads as well as writes. Every
			// preview must work with no credentials too.
			path := filepath.Join(dir, "dj", "oauth-tokens.json")
			for _, present := range []bool{false, true} {
				if present {
					os.MkdirAll(filepath.Dir(path), 0700)
					os.WriteFile(path, []byte("not valid credentials"), 0600)
				}
				args := append(append([]string{}, prefix...), tc.args...)
				args = append(args, "--dry-run")
				code, out := runCommand(t, args...)
				if code != 0 || out["ok"] != true {
					t.Fatalf("dry run failed: %d %#v", code, out)
				}
				data := out["data"].(map[string]any)
				if data["url"] != server.URL+tc.path || data["method"] != tc.method {
					t.Fatalf("bad preview: %#v", data)
				}
				// Pagination details include traversal options; other previews expose the exact body.
				if tc.name != "album_tracks" && !reflect.DeepEqual(data["details"], tc.body) {
					t.Errorf("preview body=%#v want=%#v", data["details"], tc.body)
				}
				if calls != 0 {
					t.Fatal("dry-run made network request")
				}
				if present {
					data, _ := os.ReadFile(path)
					if string(data) != "not valid credentials" {
						t.Fatal("preview changed credentials")
					}
				} else if _, err := os.Stat(filepath.Join(dir, "dj")); !os.IsNotExist(err) {
					t.Fatal("preview created configuration")
				}
			}
			os.Remove(path)
			if err := oauth.NewOAuthStore(path).Save("default", oauth.TokenSet{AccessToken: "fake-token", ExpiresAt: time.Now().Add(time.Hour)}); err != nil {
				t.Fatal(err)
			}
			args := append(append([]string{}, prefix...), tc.args...)
			args = append(args, "--yes")
			code, out := runCommand(t, args...)
			if code != 0 {
				t.Fatalf("execution: %d %#v", code, out)
			}
			if calls != 1 {
				t.Fatalf("got %d requests", calls)
			}
		})
	}
}

func TestPlaybackEmptyAndNullState(t *testing.T) {
	for _, command := range []string{"status", "now-playing"} {
		for _, status := range []int{http.StatusNoContent, http.StatusOK} {
			t.Run(command+http.StatusText(status), func(t *testing.T) {
				dir := t.TempDir()
				t.Setenv("XDG_CONFIG_HOME", dir)
				path := filepath.Join(dir, "dj", "oauth-tokens.json")
				if err := oauth.NewOAuthStore(path).Save("default", oauth.TokenSet{AccessToken: "fake", ExpiresAt: time.Now().Add(time.Hour)}); err != nil {
					t.Fatal(err)
				}
				server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					w.WriteHeader(status)
					if status == http.StatusOK {
						io.WriteString(w, `{"is_playing":false,"item":null}`)
					}
				}))
				defer server.Close()
				code, out := runCommand(t, "--auth-storage", "file", "--base-url", server.URL, "player", command)
				if code != 0 {
					t.Fatalf("code %d %#v", code, out)
				}
				if status == http.StatusNoContent {
					if out["data"] != nil {
						t.Fatalf("invented playback state: %#v", out)
					}
				} else if data := out["data"].(map[string]any); data["item"] != nil {
					t.Fatalf("invented playback item: %#v", data)
				}
			})
		}
	}
}

func TestDeclinedPlaybackDoesNotResolveCredentials(t *testing.T) {
	for _, name := range []string{"play", "pause", "next", "previous"} {
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			t.Setenv("XDG_CONFIG_HOME", dir)
			code, out := runCommand(t, "--auth-storage", "file", "player", name)
			if code != 0 || out["data"].(map[string]any)["status"] != "cancelled" {
				t.Fatalf("unexpected cancellation: %d %#v", code, out)
			}
			if _, err := os.Stat(filepath.Join(dir, "dj")); !os.IsNotExist(err) {
				t.Fatal("declining touched config")
			}
		})
	}
}
