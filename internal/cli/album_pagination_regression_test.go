package cli

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"reflect"
	"strconv"
	"testing"
	"time"

	"github.com/Scale-Flow/marten/pkg/oauth"
)

func albumTestCredentials(t *testing.T) {
	t.Helper()
	dir := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", dir)
	t.Setenv("DJ_PROFILE", "")
	t.Setenv("DJ_BASE_URL", "")
	path := filepath.Join(dir, "dj", "oauth-tokens.json")
	if err := oauth.NewOAuthStore(path).Save("default", oauth.TokenSet{AccessToken: "fake-token", ExpiresAt: time.Now().Add(time.Hour)}); err != nil {
		t.Fatal(err)
	}
}

func TestAlbumTracksCommandPagination(t *testing.T) {
	cases := []struct {
		name      string
		flags     []string
		nextLinks bool
		offsets   []int
		ids       []string
		lastPage  int
	}{
		{"single_page", []string{"--page", "2"}, true, []int{2}, []string{"track-2", "track-3"}, 2},
		{"all_pages", []string{"--all"}, true, []int{0, 2, 4}, []string{"track-0", "track-1", "track-2", "track-3", "track-4"}, 3},
		{"all_ignores_single_page", []string{"--all", "--page", "3"}, true, []int{0, 2, 4}, []string{"track-0", "track-1", "track-2", "track-3", "track-4"}, 3},
		{"bounded_all", []string{"--all", "--max-pages", "2"}, true, []int{0, 2}, []string{"track-0", "track-1", "track-2", "track-3"}, 2},
		{"total_without_next", []string{"--all"}, false, []int{0, 2, 4}, []string{"track-0", "track-1", "track-2", "track-3", "track-4"}, 3},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			albumTestCredentials(t)
			offsets := []int{}
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path != "/v1/albums/album1/tracks" || r.URL.Query().Get("market") != "GB" || r.URL.Query().Get("limit") != "2" {
					t.Errorf("wrong request: %s", r.URL)
				}
				if r.URL.Query().Has("page") || r.URL.Query().Has("per_page") {
					t.Errorf("unsupported Spotify pagination: %s", r.URL)
				}
				if r.Header.Get("Authorization") != "Bearer fake-token" {
					t.Error("missing fake authorization")
				}
				offset, err := strconv.Atoi(r.URL.Query().Get("offset"))
				if err != nil {
					t.Error(err)
				}
				offsets = append(offsets, offset)
				items := []map[string]string{}
				for i := offset; i < offset+2 && i < 5; i++ {
					items = append(items, map[string]string{"id": fmt.Sprintf("track-%d", i)})
				}
				var next any
				if tc.nextLinks && offset+2 < 5 {
					// Only the offset is trusted. The next request must retain the configured
					// host and market, never forward the bearer token to this external URL.
					next = fmt.Sprintf("https://untrusted.invalid/v1/albums/album1/tracks?offset=%d&limit=2", offset+2)
				}
				json.NewEncoder(w).Encode(map[string]any{"items": items, "limit": 2, "offset": offset, "total": 5, "next": next})
			}))
			defer srv.Close()
			args := []string{"--auth-storage", "file", "--base-url", srv.URL, "albums", "tracks", "--id", "album1", "--market", "GB", "--per-page", "2"}
			code, out := runCommand(t, append(args, tc.flags...)...)
			if code != 0 || out["ok"] != true {
				t.Fatalf("command failed: %d %#v", code, out)
			}
			if !reflect.DeepEqual(offsets, tc.offsets) {
				t.Fatalf("offsets=%v want=%v", offsets, tc.offsets)
			}
			ids := []string{}
			for _, item := range out["data"].([]any) {
				ids = append(ids, item.(map[string]any)["id"].(string))
			}
			if !reflect.DeepEqual(ids, tc.ids) {
				t.Fatalf("items=%v want=%v", ids, tc.ids)
			}
			pagination := out["meta"].(map[string]any)["pagination"].(map[string]any)
			want := map[string]any{"page": float64(tc.lastPage), "per_page": float64(2), "total_count": float64(5), "total_pages": float64(3)}
			if !reflect.DeepEqual(pagination, want) {
				t.Fatalf("metadata=%v want=%v", pagination, want)
			}
		})
	}
}

func TestAlbumTracksPaginationValidationBeforeAuth(t *testing.T) {
	for _, flags := range [][]string{{"--page", "0"}, {"--page", "-1"}, {"--per-page", "0"}, {"--per-page", "51"}, {"--max-pages", "0"}} {
		t.Run(fmt.Sprint(flags), func(t *testing.T) {
			t.Setenv("XDG_CONFIG_HOME", t.TempDir())
			code, out := runCommand(t, append([]string{"--auth-storage", "file", "albums", "tracks", "--id", "album1"}, flags...)...)
			if code != 2 || out["error"].(map[string]any)["code"] != "validation_error" {
				t.Fatalf("got %d %#v", code, out)
			}
		})
	}
}

func TestAlbumTracksRejectsNonAdvancingPagination(t *testing.T) {
	albumTestCredentials(t)
	calls := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		fmt.Fprint(w, `{"items":[{"id":"a"}],"offset":0,"limit":1,"total":2,"next":"https://api.spotify.com/v1/albums/album1/tracks?offset=0"}`)
	}))
	defer srv.Close()
	code, out := runCommand(t, "--auth-storage", "file", "--base-url", srv.URL, "albums", "tracks", "--id", "album1", "--per-page", "1", "--all")
	if code != 1 || out["ok"] != false || calls != 1 {
		t.Fatalf("code=%d calls=%d response=%#v", code, calls, out)
	}
}

func TestCommandPreservesAPIAndNetworkErrors(t *testing.T) {
	for _, tc := range []struct {
		status, exit int
		code         string
	}{
		{400, 2, "validation_error"}, {401, 3, "unauthorized"}, {403, 3, "forbidden"}, {404, 1, "not_found"}, {429, 4, "rate_limited"}, {500, 1, "server_error"},
	} {
		t.Run(strconv.Itoa(tc.status), func(t *testing.T) {
			albumTestCredentials(t)
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Retry-After", "0")
				w.WriteHeader(tc.status)
				fmt.Fprintf(w, `{"error":{"status":%d,"message":"Spotify diagnostic"}}`, tc.status)
			}))
			defer srv.Close()
			code, out := runCommand(t, "--auth-storage", "file", "--base-url", srv.URL, "albums", "tracks", "--id", "album1")
			if code != tc.exit || out["ok"] != false {
				t.Fatalf("code=%d response=%#v", code, out)
			}
			detail := out["error"].(map[string]any)
			if detail["code"] != tc.code || detail["message"] != "Spotify diagnostic" {
				t.Fatalf("wrong error: %#v", detail)
			}
			data := detail["detail"].(map[string]any)
			if data["status_code"] != float64(tc.status) || data["retry_after"] != "0" {
				t.Fatalf("lost API metadata: %#v", data)
			}
		})
	}
	t.Run("network", func(t *testing.T) {
		albumTestCredentials(t)
		srv := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
		srv.Close()
		code, out := runCommand(t, "--auth-storage", "file", "--base-url", srv.URL, "albums", "tracks", "--id", "album1")
		if code != 5 || out["error"].(map[string]any)["code"] != "network_error" {
			t.Fatalf("code=%d response=%#v", code, out)
		}
	})
}
