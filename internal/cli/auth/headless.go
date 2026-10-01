package auth

import (
	"bufio"
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"time"

	"github.com/Scale-Flow/marten/pkg/cmdutil"
	"github.com/Scale-Flow/marten/pkg/contract"
	"github.com/Scale-Flow/marten/pkg/oauth"
	"github.com/spf13/cobra"
	"golang.org/x/term"
)

const headlessRedirect = "http://127.0.0.1:8085/callback"
const sessionLifetime = 10 * time.Minute

type loginSession struct {
	Profile  string    `json:"profile"`
	ClientID string    `json:"client_id"`
	State    string    `json:"state"`
	Verifier string    `json:"verifier"`
	Expires  time.Time `json:"expires_at"`
}

func spotifyPKCEConfig(clientID string) oauth.AuthCodeConfig {
	return oauth.AuthCodeConfig{AuthURL: "https://accounts.spotify.com/authorize", TokenURL: "https://accounts.spotify.com/api/token", ClientID: clientID, RedirectURI: headlessRedirect, Scopes: []string{"user-read-currently-playing", "user-read-playback-state", "user-modify-playback-state"}}
}

func addHeadlessCommands(login *cobra.Command) {
	for _, action := range []string{"start", "complete", "cancel"} {
		action := action
		cmd := &cobra.Command{Use: action, Short: map[string]string{"start": "Start a private, ten-minute headless PKCE login (no browser or relay)", "complete": "Complete headless login from a callback URL on stdin (never an argument)", "cancel": "Discard a pending headless login"}[action], Args: cobra.NoArgs}
		if action == "start" {
			cmd.Flags().String("client-id", "", "Spotify app Client ID (or DJ_CLIENT_ID); no client secret needed")
		}
		cmd.RunE = func(cmd *cobra.Command, _ []string) error { return runHeadless(cmd, action) }
		login.AddCommand(cmd)
	}
}

func sessionPath(profile string) (string, error) {
	tokenPath, err := oauthStorePath()
	if err != nil {
		return "", err
	}
	dir := filepath.Join(filepath.Dir(tokenPath), "pending-login")
	if err := os.MkdirAll(dir, 0700); err != nil {
		return "", errors.New("cannot create private login directory")
	}
	info, err := os.Lstat(dir)
	if err != nil || !info.IsDir() || info.Mode().Perm()&0077 != 0 {
		return "", errors.New("pending-login directory must be a private directory (0700)")
	}
	return filepath.Join(dir, fmt.Sprintf("%x.json", sha256.Sum256([]byte(profile)))), nil
}

func saveSession(path string, session loginSession) error {
	data, err := json.Marshal(session)
	if err != nil {
		return err
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return errors.New("a login is already pending, or session storage is unavailable; use auth login cancel before starting again")
	}
	_, err = f.Write(data)
	closeErr := f.Close()
	if err != nil || closeErr != nil {
		os.Remove(path)
		return errors.New("could not save private login session")
	}
	return nil
}

func loadSession(path, profile string, now time.Time) (loginSession, error) {
	var s loginSession
	info, err := os.Lstat(path)
	if err != nil {
		return s, errors.New("no pending login; run auth login start")
	}
	if !info.Mode().IsRegular() || info.Mode().Perm()&0077 != 0 {
		return s, errors.New("login session must be a private regular file (0600)")
	}
	f, err := os.Open(path)
	if err != nil {
		return s, errors.New("cannot read login session")
	}
	defer f.Close()
	if json.NewDecoder(io.LimitReader(f, 8192)).Decode(&s) != nil {
		return s, errors.New("invalid login session; cancel it and start again")
	}
	if s.Profile != profile || s.ClientID == "" || s.State == "" || len(s.Verifier) < 43 {
		return s, errors.New("invalid login session; cancel it and start again")
	}
	if !now.Before(s.Expires) || s.Expires.After(now.Add(sessionLifetime+time.Second)) {
		return s, errors.New("login session expired or invalid; cancel it and start again")
	}
	return s, nil
}

func callbackCode(raw string, s loginSession) (string, error) {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil {
		return "", errors.New("invalid callback URL")
	}
	base, _ := url.Parse(headlessRedirect)
	if u.Scheme != base.Scheme || u.Host != base.Host || u.Path != base.Path || u.User != nil || u.Fragment != "" || u.RawPath != "" {
		return "", errors.New("callback URL does not match this login's redirect URI")
	}
	q, err := url.ParseQuery(u.RawQuery)
	if err != nil {
		return "", errors.New("invalid callback query")
	}
	for _, k := range []string{"state", "code", "error"} {
		if len(q[k]) > 1 {
			return "", errors.New("duplicate callback parameters")
		}
	}
	if s.State == "" || subtle.ConstantTimeCompare([]byte(q.Get("state")), []byte(s.State)) != 1 {
		return "", errors.New("callback state mismatch; use the URL from this login only")
	}
	if q.Get("error") != "" {
		return "", errors.New("Spotify authorization was declined; cancel and start again")
	}
	if q.Get("code") == "" {
		return "", errors.New("callback is missing its authorization code")
	}
	return q.Get("code"), nil
}

// Callback input stays out of argv, shell history, normal output and chat.
func readCallback(ctx context.Context, in io.Reader, out io.Writer) (string, error) {
	type result struct {
		text string
		err  error
	}
	ch := make(chan result, 1)
	if err := ctx.Err(); err != nil {
		return "", errors.New("callback input timed out or was cancelled; session remains pending")
	}
	// Restore terminal echo even when the read is interrupted by our deadline.
	if f, ok := in.(*os.File); ok && term.IsTerminal(int(f.Fd())) {
		state, err := term.GetState(int(f.Fd()))
		if err != nil {
			return "", errors.New("cannot secure terminal input")
		}
		defer term.Restore(int(f.Fd()), state)
	}
	go func() {
		if f, ok := in.(*os.File); ok && term.IsTerminal(int(f.Fd())) {
			fmt.Fprint(out, "Paste the callback URL here (hidden), then press Enter: ")
			b, e := term.ReadPassword(int(f.Fd()))
			fmt.Fprintln(out)
			ch <- result{string(b), e}
			return
		}
		b, e := bufio.NewReader(io.LimitReader(in, 16385)).ReadString('\n')
		if e == io.EOF && len(b) > 0 {
			e = nil
		}
		if len(b) > 16384 {
			e = errors.New("callback input too long")
		}
		ch <- result{b, e}
	}()
	select {
	case r := <-ch:
		if r.err != nil {
			return "", errors.New("cannot read callback URL from stdin")
		}
		return r.text, nil
	case <-ctx.Done():
		return "", errors.New("callback input timed out or was cancelled; session remains pending")
	}
}

// Injected dependencies make completion testable without real grants or tokens.
func completeSession(ctx context.Context, path string, s loginSession, raw string, exchange func(context.Context, oauth.AuthCodeConfig, string, string) (*oauth.TokenSet, error), persist func(string, oauth.ClientCredentials, *oauth.TokenSet) (string, error)) (string, error) {
	if !time.Now().Before(s.Expires) {
		return "", errors.New("login session expired; cancel and start again")
	}
	code, err := callbackCode(raw, s)
	if err != nil {
		return "", err
	}
	// An exclusive claim prevents simultaneous/replayed exchanges. A failed exchange
	// also consumes the session: the server may already have redeemed the code.
	claimPath := fmt.Sprintf("%s.%x.claim", path, sha256.Sum256([]byte(s.State)))
	claim, err := os.OpenFile(claimPath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return "", errors.New("login is already being completed; start again after it finishes")
	}
	claim.Close()
	defer os.Remove(claimPath)
	current, err := loadSession(path, s.Profile, time.Now())
	if err != nil || current.State != s.State {
		return "", errors.New("login session changed or was consumed; start again")
	}
	if err := os.Remove(path); err != nil {
		return "", errors.New("login session was already consumed; start again")
	}
	ts, err := exchange(ctx, spotifyPKCEConfig(s.ClientID), code, s.Verifier)
	if err != nil {
		return "", errors.New("Spotify token exchange failed or timed out; check connectivity and app redirect settings, then start a new login")
	}
	if ts == nil || ts.AccessToken == "" {
		return "", errors.New("Spotify returned an invalid token response; start a new login")
	}
	source, err := persist(s.Profile, oauth.ClientCredentials{ClientID: s.ClientID}, ts)
	if err != nil {
		return "", errors.New("could not save login credentials; start again after checking credential storage")
	}
	return source, nil
}

func runHeadless(cmd *cobra.Command, action string) error {
	rctx, err := cmdutil.ResolveContext(cmd, "dj", "DJ")
	if err != nil {
		return cmdutil.WriteError(cmd, contract.ErrCodeConfig, err.Error())
	}
	dry, _ := cmd.Flags().GetBool("dry-run")
	if dry {
		return cmdutil.WriteSuccess(cmd, map[string]any{"dry_run": true, "action": "auth login " + action, "redirect_uri": headlessRedirect})
	}
	path, err := sessionPath(rctx.ProfileName)
	if err != nil {
		return cmdutil.WriteError(cmd, contract.ErrCodeConfig, err.Error())
	}
	fail := func(e error) error { return cmdutil.WriteError(cmd, contract.ErrCodeAuth, e.Error()) }
	switch action {
	case "start":
		id, _ := cmd.Flags().GetString("client-id")
		if id == "" {
			id = os.Getenv("DJ_CLIENT_ID")
		}
		id = strings.TrimSpace(id)
		if id == "" {
			return cmdutil.WriteError(cmd, contract.ErrCodeConfig, "set DJ_CLIENT_ID or --client-id; PKCE needs no client secret")
		}
		result, err := oauth.BuildAuthURLWithState(spotifyPKCEConfig(id))
		if err != nil {
			return fail(errors.New("could not create PKCE login"))
		}
		s := loginSession{Profile: rctx.ProfileName, ClientID: id, State: result.State, Verifier: result.Verifier, Expires: time.Now().Add(sessionLifetime)}
		if err := saveSession(path, s); err != nil {
			return fail(err)
		}
		fmt.Fprintln(cmd.ErrOrStderr(), "Register "+headlessRedirect+" in your Spotify app. Open authorization_url in your own browser. After authorization, use the full callback address with auth login complete in your private terminal. Never share callback URLs in chat, logs, or command arguments. No local listener is started; a browser connection error at the redirect is expected.")
		return cmdutil.WriteSuccess(cmd, map[string]any{"status": "pending", "profile": s.Profile, "authorization_url": result.URL, "expires_at": s.Expires, "redirect_uri": headlessRedirect})
	case "cancel":
		if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
			return fail(errors.New("cannot discard login session"))
		}
		return cmdutil.WriteSuccess(cmd, map[string]any{"status": "cancelled", "profile": rctx.ProfileName})
	default:
		s, err := loadSession(path, rctx.ProfileName, time.Now())
		if err != nil {
			return fail(err)
		}
		ctx, stop := signal.NotifyContext(cmd.Context(), os.Interrupt)
		defer stop()
		ctx, cancel := context.WithDeadline(ctx, s.Expires)
		defer cancel()
		raw, err := readCallback(ctx, cmd.InOrStdin(), cmd.ErrOrStderr())
		if err != nil {
			return fail(err)
		}
		exchangeCtx, cancelExchange := context.WithTimeout(ctx, 30*time.Second)
		defer cancelExchange()
		source, err := completeSession(exchangeCtx, path, s, raw, oauth.ExchangeCode, persistOAuthLogin)
		if err != nil {
			return fail(err)
		}
		return cmdutil.WriteSuccess(cmd, map[string]any{"status": "authenticated", "profile": s.Profile, "source": source})
	}
}
