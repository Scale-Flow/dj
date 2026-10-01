package auth

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
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
	"github.com/spf13/cobra"
)

func sampleSession() loginSession {
	return loginSession{Profile: "test", ClientID: "test-client", State: "test-state", Verifier: strings.Repeat("v", 64), Expires: time.Now().Add(time.Minute)}
}
func sampleCallback() string { return headlessRedirect + "?state=test-state&code=test-code" }
func TestCallbackValidation(t *testing.T) {
	for _, q := range []string{headlessRedirect + "?code=x", headlessRedirect + "?state=wrong&code=x", headlessRedirect + "?state=test-state", headlessRedirect + "?state=test-state&error=access_denied", headlessRedirect + "?state=test-state&code=a&code=b", headlessRedirect + "?state=test-state&state=test-state&code=x", strings.Replace(sampleCallback(), "127.0.0.1", "evil.example", 1), sampleCallback() + "#fragment", sampleCallback() + "%zz"} {
		if _, e := callbackCode(q, sampleSession()); e == nil {
			t.Errorf("accepted invalid callback %s", q)
		}
	}
	if code, e := callbackCode(sampleCallback(), sampleSession()); e != nil || code != "test-code" {
		t.Fatal("valid callback rejected")
	}
}
func TestSessionPermissionsExpiryAndProfile(t *testing.T) {
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	p, e := sessionPath("test")
	if e != nil {
		t.Fatal(e)
	}
	if e = saveSession(p, sampleSession()); e != nil {
		t.Fatal(e)
	}
	for _, item := range []struct {
		path string
		want os.FileMode
	}{{p, 0600}, {filepath.Dir(p), 0700}} {
		i, _ := os.Stat(item.path)
		if i.Mode().Perm() != item.want {
			t.Fatal("unsafe permissions")
		}
	}
	if e = saveSession(p, sampleSession()); e == nil {
		t.Fatal("overwrote session")
	}
	if _, e = loadSession(p, "other", time.Now()); e == nil {
		t.Fatal("profile mismatch accepted")
	}
	if _, e = loadSession(p, "test", time.Now().Add(2*time.Minute)); e == nil {
		t.Fatal("expiry ignored")
	}
	os.Chmod(p, 0644)
	if _, e = loadSession(p, "test", time.Now()); e == nil {
		t.Fatal("unsafe file accepted")
	}
	os.Remove(p)
	os.Symlink(filepath.Join(t.TempDir(), "missing"), p)
	if _, e = loadSession(p, "test", time.Now()); e == nil {
		t.Fatal("symlink accepted")
	}
	os.Chmod(filepath.Dir(p), 0755)
	if _, e = sessionPath("test"); e == nil {
		t.Fatal("unsafe directory accepted")
	}
}
func TestCompleteMockSpotifyAndReplay(t *testing.T) {
	s := sampleSession()
	path := filepath.Join(t.TempDir(), "session")
	if e := saveSession(path, s); e != nil {
		t.Fatal(e)
	}
	calls := 0
	stored := false
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		r.ParseForm()
		for k, v := range map[string]string{"code": "test-code", "code_verifier": s.Verifier, "client_id": s.ClientID, "redirect_uri": headlessRedirect, "grant_type": "authorization_code"} {
			if r.Form.Get(k) != v {
				t.Errorf("wrong %s", k)
			}
		}
		if r.Form.Get("client_secret") != "" {
			t.Error("secret used in PKCE")
		}
		io.WriteString(w, `{"access_token":"mock-access","refresh_token":"mock-refresh","token_type":"Bearer","expires_in":3600}`)
	}))
	defer srv.Close()
	exchange := func(ctx context.Context, cfg oauth.AuthCodeConfig, code, verifier string) (*oauth.TokenSet, error) {
		cfg.TokenURL = srv.URL
		return oauth.ExchangeCode(ctx, cfg, code, verifier)
	}
	persist := func(profile string, creds oauth.ClientCredentials, ts *oauth.TokenSet) (string, error) {
		stored = true
		if profile != s.Profile || creds.ClientID != s.ClientID || creds.ClientSecret != "" || ts.AccessToken != "mock-access" {
			t.Error("wrong persistence data")
		}
		return "mock", nil
	}
	if _, e := completeSession(context.Background(), path, s, sampleCallback(), exchange, persist); e != nil {
		t.Fatal(e)
	}
	if !stored || calls != 1 {
		t.Fatal("login did not complete")
	}
	if _, e := completeSession(context.Background(), path, s, sampleCallback(), exchange, persist); e == nil {
		t.Fatal("replay accepted")
	}
	if calls != 1 {
		t.Fatal("replay sent to provider")
	}
}
func TestCompletionFailureConsumesAndRedacts(t *testing.T) {
	s := sampleSession()
	p := filepath.Join(t.TempDir(), "session")
	saveSession(p, s)
	exchange := func(context.Context, oauth.AuthCodeConfig, string, string) (*oauth.TokenSet, error) {
		return nil, errors.New("secret-verifier-and-code")
	}
	_, e := completeSession(context.Background(), p, s, sampleCallback(), exchange, nil)
	if e == nil || strings.Contains(e.Error(), "secret-verifier") {
		t.Fatal("error not redacted")
	}
	if _, e = os.Stat(p); !os.IsNotExist(e) {
		t.Fatal("failed exchange not consumed")
	}
}
func TestWrongCallbackKeepsSession(t *testing.T) {
	s := sampleSession()
	p := filepath.Join(t.TempDir(), "session")
	saveSession(p, s)
	if _, e := completeSession(context.Background(), p, s, "bad", nil, nil); e == nil {
		t.Fatal("bad callback accepted")
	}
	if _, e := os.Stat(p); e != nil {
		t.Fatal("invalid callback consumed session")
	}
}
func TestCallbackInput(t *testing.T) {
	if got, e := readCallback(context.Background(), strings.NewReader(sampleCallback()+"\n"), io.Discard); e != nil || strings.TrimSpace(got) != sampleCallback() {
		t.Fatal("input failure")
	}
	if _, e := readCallback(context.Background(), strings.NewReader(strings.Repeat("x", 17000)), io.Discard); e == nil {
		t.Fatal("oversize accepted")
	}
	r, w := io.Pipe()
	defer r.Close()
	defer w.Close()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, e := readCallback(ctx, r, io.Discard); e == nil {
		t.Fatal("cancellation ignored")
	}
}
func TestHeadlessCommandStartCancelDryRun(t *testing.T) {
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	t.Setenv("DJ_CLIENT_ID", "mock-client")
	run := func(args ...string) (string, error) {
		root := &cobra.Command{Use: "dj"}
		root.PersistentFlags().String("profile", "test", "")
		root.PersistentFlags().Bool("dry-run", false, "")
		root.PersistentFlags().Bool("pretty", false, "")
		root.AddCommand(NewAuthCmd())
		old := os.Stdout
		r, w, err := os.Pipe()
		if err != nil {
			t.Fatal(err)
		}
		os.Stdout = w
		defer func() { os.Stdout = old; r.Close() }()
		root.SetErr(io.Discard)
		root.SetArgs(args)
		e := root.Execute()
		w.Close()
		b, _ := io.ReadAll(r)
		return string(b), e
	}
	if _, e := run("auth", "login", "start", "--dry-run"); e != nil {
		t.Fatal(e)
	}
	p, _ := sessionPath("test")
	if _, e := os.Stat(p); !os.IsNotExist(e) {
		t.Fatal("dry-run created session")
	}
	out, e := run("auth", "login", "start")
	if e != nil {
		t.Fatal(e)
	}
	var result struct {
		Data struct {
			URL string `json:"authorization_url"`
		}
	}
	json.Unmarshal([]byte(out), &result)
	u, e := url.Parse(result.Data.URL)
	if e != nil || u.Host != "accounts.spotify.com" {
		t.Fatal("missing authorization URL")
	}
	s, e := loadSession(p, "test", time.Now())
	if e != nil {
		t.Fatal(e)
	}
	sum := sha256.Sum256([]byte(s.Verifier))
	if u.Query().Get("code_challenge") != base64.RawURLEncoding.EncodeToString(sum[:]) || u.Query().Get("code_challenge_method") != "S256" {
		t.Fatal("incorrect PKCE")
	}
	if strings.Contains(out, s.Verifier) {
		t.Fatal("verifier leaked")
	}
	if _, e := run("auth", "login", "start"); e == nil {
		t.Fatal("duplicate login accepted")
	}
	if _, e := run("auth", "login", "cancel"); e != nil {
		t.Fatal(e)
	}
}
func TestLocalLoginDeadline(t *testing.T) {
	t.Setenv("DJ_CLIENT_ID", "mock-client")
	cmd := newAuthLoginCmd()
	cmd.SetContext(context.Background())
	cmd.SetOut(io.Discard)
	cmd.SetErr(io.Discard)
	cmd.SetArgs([]string{"--local", "--timeout", "1ns"})
	started := time.Now()
	if e := cmd.Execute(); e == nil {
		t.Fatal("expected timeout")
	}
	if time.Since(started) > time.Second {
		t.Fatal("login did not terminate")
	}
}

func TestRelayErrorReturnsImmediately(t *testing.T) {
	old := pollForAuthCode
	defer func() { pollForAuthCode = old }()
	pollForAuthCode = func(context.Context, string, string, time.Duration, time.Duration) (string, error) {
		return "", errors.New("mock relay timeout")
	}
	cmd := newAuthLoginCmd()
	cmd.SetContext(context.Background())
	cmd.SetIn(strings.NewReader(""))
	cmd.SetOut(io.Discard)
	cmd.SetErr(io.Discard)
	started := time.Now()
	if err := runManualCodeFlow(cmd, "test", oauth.ClientCredentials{ClientID: "mock-client"}); err == nil {
		t.Fatal("relay error swallowed")
	}
	if time.Since(started) > time.Second {
		t.Fatal("relay hung")
	}
}

func TestStaleCompletionCannotConsumeNewSession(t *testing.T) {
	s := sampleSession()
	p := filepath.Join(t.TempDir(), "session")
	newer := s
	newer.State = "new-state"
	saveSession(p, newer)
	if _, err := completeSession(context.Background(), p, s, sampleCallback(), nil, nil); err == nil {
		t.Fatal("stale session accepted")
	}
	if got, err := loadSession(p, s.Profile, time.Now()); err != nil || got.State != newer.State {
		t.Fatal("new session consumed")
	}
}
func TestConcurrentCompletionsExchangeOnce(t *testing.T) {
	s := sampleSession()
	p := filepath.Join(t.TempDir(), "session")
	saveSession(p, s)
	entered, release, done := make(chan struct{}), make(chan struct{}), make(chan error, 1)
	exchange := func(context.Context, oauth.AuthCodeConfig, string, string) (*oauth.TokenSet, error) {
		close(entered)
		<-release
		return &oauth.TokenSet{AccessToken: "mock"}, nil
	}
	persist := func(string, oauth.ClientCredentials, *oauth.TokenSet) (string, error) { return "mock", nil }
	go func() {
		_, err := completeSession(context.Background(), p, s, sampleCallback(), exchange, persist)
		done <- err
	}()
	<-entered
	if _, err := completeSession(context.Background(), p, s, sampleCallback(), nil, nil); err == nil {
		t.Error("concurrent completion accepted")
	}
	close(release)
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

func TestCallbackBracketedPaste(t *testing.T) {
	for _, raw := range []string{"\x1b[200~" + sampleCallback() + "\x1b[201~", " \x1b[200~" + sampleCallback() + "\x1b[201~\n"} {
		code, err := callbackCode(raw, sampleSession())
		if err != nil || code != "test-code" {
			t.Fatal("bracketed paste rejected")
		}
	}
}
func TestExplicitFileStorage(t *testing.T) {
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	source, err := persistOAuthLoginWithBackend("mock", oauth.ClientCredentials{ClientID: "mock-client"}, &oauth.TokenSet{AccessToken: "mock-access", RefreshToken: "mock-refresh"}, "file")
	if err != nil || source != "file" {
		t.Fatalf("file storage failed: %v", err)
	}
	p, _ := oauthStorePath()
	i, err := os.Stat(p)
	if err != nil || i.Mode().Perm() != 0600 {
		t.Fatal("token file not private")
	}
}
