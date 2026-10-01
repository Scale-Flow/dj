package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Scale-Flow/marten/pkg/oauth"
	"github.com/scale-flow/dj/internal/cli/cliutil"
)

type backendTokenSpy struct{ loads, saves, deletes int }

func (s *backendTokenSpy) Load(string) (*oauth.TokenSet, error) {
	s.loads++
	return nil, oauth.ErrTokenNotFound
}
func (s *backendTokenSpy) Save(string, oauth.TokenSet) error { s.saves++; return nil }
func (s *backendTokenSpy) Delete(string) error               { s.deletes++; return nil }

type backendCredentialSpy struct{ loads, saves, deletes int }

func (s *backendCredentialSpy) Load(string) (*oauth.ClientCredentials, error) {
	s.loads++
	return &oauth.ClientCredentials{ClientID: "stale-keychain-id", ClientSecret: "stale-keychain-secret"}, nil
}
func (s *backendCredentialSpy) Save(string, oauth.ClientCredentials) error { s.saves++; return nil }
func (s *backendCredentialSpy) Delete(string) error                        { s.deletes++; return nil }

type backendRoundTrip func(*http.Request) (*http.Response, error)

func (f backendRoundTrip) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func runBackendCommand(t *testing.T, ctx context.Context, input string, args ...string) (string, error) {
	t.Helper()
	root := NewRootCmd("test")
	root.SetContext(ctx)
	root.SetIn(strings.NewReader(input))
	root.SetErr(io.Discard)
	root.SetArgs(args)
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	old := os.Stdout
	os.Stdout = w
	defer func() { os.Stdout = old; r.Close() }()
	err = root.Execute()
	w.Close()
	b, readErr := io.ReadAll(r)
	if readErr != nil {
		t.Fatal(readErr)
	}
	return string(b), err
}

func backendTestStores(t *testing.T) (context.Context, string, *backendTokenSpy, *backendCredentialSpy) {
	t.Helper()
	dir := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", dir)
	t.Setenv("DJ_PROFILE", "")
	path := filepath.Join(dir, "dj", "oauth-tokens.json")
	keyTokens, keyCreds := &backendTokenSpy{}, &backendCredentialSpy{}
	ctx := cliutil.WithAuthStores(context.Background(), cliutil.AuthStores{KeychainTokens: keyTokens, KeychainCredentials: keyCreds, FileTokens: oauth.NewOAuthStore(path), FileCredentials: oauth.NewClientCredentialFileStore(oauth.ClientCredentialPathForTokenStore(path))})
	return ctx, path, keyTokens, keyCreds
}

func TestStatusCommandHonorsBackendWithoutMigration(t *testing.T) {
	for _, mode := range []string{"file", "auto"} {
		t.Run(mode, func(t *testing.T) {
			ctx, path, keys, clients := backendTestStores(t)
			if err := oauth.NewOAuthStore(path).Save("default", oauth.TokenSet{AccessToken: "fake-file-token", ExpiresAt: time.Now().Add(time.Hour)}); err != nil {
				t.Fatal(err)
			}
			if err := oauth.NewClientCredentialFileStore(oauth.ClientCredentialPathForTokenStore(path)).Save("default", oauth.ClientCredentials{ClientID: "file-client"}); err != nil {
				t.Fatal(err)
			}
			beforeTokens, _ := os.ReadFile(path)
			beforeCreds, _ := os.ReadFile(oauth.ClientCredentialPathForTokenStore(path))
			out, err := runBackendCommand(t, ctx, "", "--auth-storage", mode, "auth", "status")
			if err != nil {
				t.Fatalf("status failed: %v %s", err, out)
			}
			var result struct {
				OK   bool `json:"ok"`
				Data struct {
					Source       string `json:"source"`
					ClientSource string `json:"client_credentials_source"`
				} `json:"data"`
			}
			if err := json.Unmarshal([]byte(out), &result); err != nil || !result.OK || result.Data.Source != "file" || result.Data.ClientSource != "file" {
				t.Fatalf("wrong backend reported: %s", out)
			}
			afterTokens, _ := os.ReadFile(path)
			afterCreds, _ := os.ReadFile(oauth.ClientCredentialPathForTokenStore(path))
			if !bytes.Equal(beforeTokens, afterTokens) || !bytes.Equal(beforeCreds, afterCreds) {
				t.Fatal("status mutated file storage")
			}
			if keys.saves+keys.deletes+clients.loads+clients.saves+clients.deletes != 0 {
				t.Fatal("status migrated or mixed client credentials")
			}
			if mode == "file" && keys.loads != 0 {
				t.Fatal("explicit file status contacted keychain")
			}
			if _, err := os.Stat(oauth.MetadataPathForTokenStore(path)); !os.IsNotExist(err) {
				t.Fatal("status wrote metadata")
			}
		})
	}
}

func TestAPICommandRefreshHonorsExplicitFile(t *testing.T) {
	ctx, path, keys, clients := backendTestStores(t)
	if err := oauth.NewOAuthStore(path).Save("default", oauth.TokenSet{AccessToken: "expired", RefreshToken: "file-refresh", ExpiresAt: time.Now().Add(-time.Hour)}); err != nil {
		t.Fatal(err)
	}
	if err := oauth.NewClientCredentialFileStore(oauth.ClientCredentialPathForTokenStore(path)).Save("default", oauth.ClientCredentials{ClientID: "file-id", ClientSecret: "file-secret"}); err != nil {
		t.Fatal(err)
	}
	refreshCalls, apiCalls := 0, 0
	oldClient := http.DefaultClient
	http.DefaultClient = &http.Client{Transport: backendRoundTrip(func(r *http.Request) (*http.Response, error) {
		refreshCalls++
		if r.URL.String() != "https://accounts.spotify.com/api/token" {
			t.Errorf("unexpected refresh destination %s", r.URL)
		}
		r.ParseForm()
		if r.Form.Get("client_id") != "file-id" || r.Form.Get("client_secret") != "file-secret" || r.Form.Get("refresh_token") != "file-refresh" {
			t.Errorf("refresh used wrong credentials: %v", r.Form)
		}
		return &http.Response{StatusCode: 200, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(`{"access_token":"refreshed","expires_in":3600}`))}, nil
	})}
	t.Cleanup(func() { http.DefaultClient = oldClient })
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		apiCalls++
		if r.Header.Get("Authorization") != "Bearer refreshed" {
			t.Error("API did not receive refreshed token")
		}
		io.WriteString(w, `{"devices":[]}`)
	}))
	defer server.Close()
	out, err := runBackendCommand(t, ctx, "", "--auth-storage", "file", "--base-url", server.URL, "player", "devices")
	if err != nil || refreshCalls != 1 || apiCalls != 1 {
		t.Fatalf("command failed: %v refresh=%d api=%d %s", err, refreshCalls, apiCalls, out)
	}
	if keys.loads+keys.saves+keys.deletes+clients.loads+clients.saves+clients.deletes != 0 {
		t.Fatal("file API refresh contacted keychain")
	}
	token, err := oauth.NewOAuthStore(path).Load("default")
	if err != nil || token.AccessToken != "refreshed" || token.RefreshToken != "file-refresh" {
		t.Fatal("refreshed token not persisted to file")
	}
}

func TestHeadlessCompletionUsesGlobalFileBackend(t *testing.T) {
	ctx, path, keys, clients := backendTestStores(t)
	out, err := runBackendCommand(t, ctx, "", "--auth-storage", "file", "auth", "login", "start", "--client-id", "file-client")
	if err != nil {
		t.Fatalf("start failed: %v %s", err, out)
	}
	var started struct {
		Data struct {
			URL string `json:"authorization_url"`
		} `json:"data"`
	}
	if err := json.Unmarshal([]byte(out), &started); err != nil {
		t.Fatal(err)
	}
	authURL, err := url.Parse(started.Data.URL)
	if err != nil {
		t.Fatal(err)
	}
	callback := "http://127.0.0.1:8085/callback?" + url.Values{"state": {authURL.Query().Get("state")}, "code": {"fake-code"}}.Encode()
	oldClient := http.DefaultClient
	exchanges := 0
	http.DefaultClient = &http.Client{Transport: backendRoundTrip(func(r *http.Request) (*http.Response, error) {
		exchanges++
		r.ParseForm()
		if r.URL.String() != "https://accounts.spotify.com/api/token" || r.Form.Get("client_id") != "file-client" || r.Form.Get("code_verifier") == "" {
			t.Error("invalid token exchange")
		}
		return &http.Response{StatusCode: 200, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(`{"access_token":"new-file-token","refresh_token":"new-refresh","expires_in":3600}`))}, nil
	})}
	t.Cleanup(func() { http.DefaultClient = oldClient })
	out, err = runBackendCommand(t, ctx, callback+"\n", "--auth-storage", "file", "auth", "login", "complete")
	if err != nil || exchanges != 1 || !strings.Contains(out, `"source":"file"`) {
		t.Fatalf("completion failed: %v %s", err, out)
	}
	if keys.loads+keys.saves+keys.deletes+clients.loads+clients.saves+clients.deletes != 0 {
		t.Fatal("file completion contacted keychain")
	}
	token, err := oauth.NewOAuthStore(path).Load("default")
	if err != nil || token.AccessToken != "new-file-token" {
		t.Fatal("login token not saved to file")
	}
	creds, err := oauth.NewClientCredentialFileStore(oauth.ClientCredentialPathForTokenStore(path)).Load("default")
	if err != nil || creds.ClientID != "file-client" || creds.ClientSecret != "" {
		t.Fatal("matching login credentials not saved to file")
	}
}

func TestExplicitKeychainStatusNeverFallsBackToFile(t *testing.T) {
	ctx, path, keys, clients := backendTestStores(t)
	if err := oauth.NewOAuthStore(path).Save("default", oauth.TokenSet{AccessToken: "file-token"}); err != nil {
		t.Fatal(err)
	}
	out, err := runBackendCommand(t, ctx, "", "--auth-storage", "keychain", "auth", "status")
	if err != nil || !strings.Contains(out, `"authenticated":false`) || keys.loads != 1 || clients.loads != 0 {
		t.Fatalf("keychain status fell back: %v %s", err, out)
	}
}
