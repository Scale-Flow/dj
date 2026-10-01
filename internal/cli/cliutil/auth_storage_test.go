package cliutil

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"github.com/Scale-Flow/marten/pkg/cmdutil"
	"github.com/Scale-Flow/marten/pkg/oauth"
)

type tokenSpy struct {
	token                 *oauth.TokenSet
	loads, saves, deletes int
	loadErr, saveErr      error
}

func (s *tokenSpy) Load(string) (*oauth.TokenSet, error) {
	s.loads++
	if s.loadErr != nil {
		return nil, s.loadErr
	}
	if s.token == nil {
		return nil, oauth.ErrTokenNotFound
	}
	v := *s.token
	return &v, nil
}
func (s *tokenSpy) Save(_ string, v oauth.TokenSet) error {
	s.saves++
	if s.saveErr != nil {
		return s.saveErr
	}
	s.token = &v
	return nil
}
func (s *tokenSpy) Delete(string) error { s.deletes++; s.token = nil; return nil }

type credentialSpy struct {
	saveErrors            []error
	creds                 *oauth.ClientCredentials
	loads, saves, deletes int
	loadErr, saveErr      error
}

func (s *credentialSpy) Load(string) (*oauth.ClientCredentials, error) {
	s.loads++
	if s.loadErr != nil {
		return nil, s.loadErr
	}
	if s.creds == nil {
		return nil, oauth.ErrClientCredentialsNotFound
	}
	v := *s.creds
	return &v, nil
}
func (s *credentialSpy) Save(_ string, v oauth.ClientCredentials) error {
	s.saves++
	if len(s.saveErrors) >= s.saves && s.saveErrors[s.saves-1] != nil {
		return s.saveErrors[s.saves-1]
	}
	if s.saveErr != nil {
		return s.saveErr
	}
	s.creds = &v
	return nil
}
func (s *credentialSpy) Delete(string) error { s.deletes++; s.creds = nil; return nil }

func TestResolveAuthRefreshUsesTokenBackend(t *testing.T) {
	for _, mode := range []string{"file", "auto", "keychain"} {
		t.Run(mode, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "oauth.json")
			fileTokens := oauth.NewOAuthStore(path)
			fileCreds := oauth.NewClientCredentialFileStore(oauth.ClientCredentialPathForTokenStore(path))
			expired := oauth.TokenSet{AccessToken: "file-expired", RefreshToken: "file-refresh", ExpiresAt: time.Now().Add(-time.Hour)}
			if err := fileTokens.Save("test", expired); err != nil {
				t.Fatal(err)
			}
			if err := fileCreds.Save("test", oauth.ClientCredentials{ClientID: "file-id", ClientSecret: "file-secret"}); err != nil {
				t.Fatal(err)
			}
			keyTokens := &tokenSpy{}
			keyCreds := &credentialSpy{creds: &oauth.ClientCredentials{ClientID: "key-id", ClientSecret: "key-secret"}}
			wantID, wantSecret, wantRefresh := "file-id", "file-secret", "file-refresh"
			if mode == "keychain" {
				keyTokens.token = &oauth.TokenSet{AccessToken: "key-expired", RefreshToken: "key-refresh", ExpiresAt: expired.ExpiresAt}
				wantID, wantSecret, wantRefresh = "key-id", "key-secret", "key-refresh"
			}
			requests := 0
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				requests++
				if err := r.ParseForm(); err != nil {
					t.Error(err)
				}
				if r.Form.Get("client_id") != wantID || r.Form.Get("client_secret") != wantSecret || r.Form.Get("refresh_token") != wantRefresh {
					t.Errorf("mixed refresh backend: %v", r.Form)
				}
				io.WriteString(w, `{"access_token":"refreshed","refresh_token":"rotated","expires_in":3600}`)
			}))
			defer server.Close()
			cfg := cmdutil.AuthConfig{Strategy: "oauth2", StorageBackend: mode, ConfigDir: "dj", ProfileName: "test", OAuthStorePath: path, AllowFileFallback: true, RefreshConfig: &oauth.RefreshConfig{TokenURL: server.URL}}
			ctx := WithAuthStores(context.Background(), AuthStores{FileTokens: fileTokens, FileCredentials: fileCreds, KeychainTokens: keyTokens, KeychainCredentials: keyCreds})
			token, err := ResolveAuth(ctx, cfg)
			if err != nil || token != "refreshed" || requests != 1 {
				t.Fatalf("refresh failed: token=%q requests=%d err=%v", token, requests, err)
			}
			if cfg.RefreshConfig.ClientID != "" || cfg.RefreshConfig.ClientSecret != "" {
				t.Fatal("mutated caller refresh config")
			}
			if mode == "file" && (keyTokens.loads+keyTokens.saves+keyTokens.deletes+keyCreds.loads+keyCreds.saves+keyCreds.deletes != 0) {
				t.Fatal("explicit file consulted keychain")
			}
			if mode == "auto" && (keyTokens.saves != 0 || keyCreds.loads != 0) {
				t.Fatal("auto migrated or mixed credentials")
			}
			stored, err := fileTokens.Load("test")
			if err != nil {
				t.Fatal(err)
			}
			if mode == "keychain" {
				if stored.AccessToken != "file-expired" || keyTokens.token.AccessToken != "refreshed" {
					t.Fatal("refresh changed the wrong backend")
				}
			} else if stored.AccessToken != "refreshed" || stored.RefreshToken != "rotated" {
				t.Fatal("refresh not saved to file")
			}
		})
	}
}

func TestMissingFileCredentialsNeverUseStaleKeychainOrMetadata(t *testing.T) {
	path := filepath.Join(t.TempDir(), "oauth.json")
	fileTokens := &tokenSpy{token: &oauth.TokenSet{AccessToken: "expired", RefreshToken: "refresh", ExpiresAt: time.Now().Add(-time.Hour)}}
	keyCreds := &credentialSpy{creds: &oauth.ClientCredentials{ClientID: "stale", ClientSecret: "stale-secret"}}
	if err := oauth.NewMetadataStore(oauth.MetadataPathForTokenStore(path)).Save("test", oauth.Metadata{ClientID: "stale-metadata"}); err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r.ParseForm()
		if r.Form.Get("client_id") != "" || r.Form.Get("client_secret") != "" {
			t.Fatal("refresh used credentials from outside selected store")
		}
		w.WriteHeader(http.StatusBadRequest)
		io.WriteString(w, `{"error":"invalid_client"}`)
	}))
	defer server.Close()
	ctx := WithAuthStores(context.Background(), AuthStores{FileTokens: fileTokens, FileCredentials: &credentialSpy{}, KeychainCredentials: keyCreds, KeychainTokens: &tokenSpy{}})
	_, err := ResolveAuth(ctx, cmdutil.AuthConfig{Strategy: "oauth2", StorageBackend: "file", ProfileName: "test", OAuthStorePath: path, RefreshConfig: &oauth.RefreshConfig{TokenURL: server.URL}})
	if err == nil || keyCreds.loads != 0 || fileTokens.saves != 0 {
		t.Fatal("missing credentials used stale data or saved an invalid refresh")
	}
}

func TestPersistOAuthBackendPairAndStrictSelection(t *testing.T) {
	for _, mode := range []string{"file", "auto", "keychain"} {
		t.Run(mode, func(t *testing.T) {
			keyTokens := &tokenSpy{}
			keyCreds := &credentialSpy{saveErr: errors.New("keychain backend unavailable")}
			fileTokens, fileCreds := &tokenSpy{}, &credentialSpy{}
			ctx := WithAuthStores(context.Background(), AuthStores{FileTokens: fileTokens, FileCredentials: fileCreds, KeychainTokens: keyTokens, KeychainCredentials: keyCreds})
			source, err := PersistOAuthLogin(ctx, cmdutil.AuthConfig{StorageBackend: mode, ProfileName: "test", AllowFileFallback: true}, oauth.ClientCredentials{ClientID: "new-id"}, &oauth.TokenSet{AccessToken: "new-token"})
			if mode == "keychain" {
				if err == nil || fileTokens.saves != 0 || fileCreds.saves != 0 {
					t.Fatal("explicit keychain silently fell back")
				}
				return
			}
			if err != nil || source != "file" || fileTokens.token.AccessToken != "new-token" || fileCreds.creds.ClientID != "new-id" {
				t.Fatalf("pair fallback failed: %s %v", source, err)
			}
			if keyTokens.saves != 0 {
				t.Fatal("saved token separately from credentials")
			}
			if mode == "file" && (keyTokens.loads+keyCreds.loads+keyCreds.saves != 0) {
				t.Fatal("explicit file used keychain")
			}
		})
	}
}

func TestAutoLoginKeepsExistingFilePair(t *testing.T) {
	keyTokens, keyCreds := &tokenSpy{}, &credentialSpy{creds: &oauth.ClientCredentials{ClientID: "stale"}}
	fileTokens := &tokenSpy{token: &oauth.TokenSet{AccessToken: "old"}}
	fileCreds := &credentialSpy{creds: &oauth.ClientCredentials{ClientID: "file"}}
	ctx := WithAuthStores(context.Background(), AuthStores{KeychainTokens: keyTokens, KeychainCredentials: keyCreds, FileTokens: fileTokens, FileCredentials: fileCreds})
	creds, err := LoadClientCredentials(ctx, "dj", "unused", "test", "auto")
	if err != nil || creds.ClientID != "file" || keyCreds.loads != 0 {
		t.Fatal("auto login mixed credentials")
	}
	source, err := PersistOAuthLogin(ctx, cmdutil.AuthConfig{StorageBackend: "auto", ProfileName: "test", AllowFileFallback: true}, *creds, &oauth.TokenSet{AccessToken: "new"})
	if err != nil || source != "file" || keyTokens.saves != 0 || keyCreds.saves != 0 {
		t.Fatal("auto login migrated existing pair")
	}
}

func TestFailedTokenSaveRestoresMatchingCredentials(t *testing.T) {
	keyTokens := &tokenSpy{token: &oauth.TokenSet{AccessToken: "old"}, saveErr: errors.New("write rejected")}
	keyCreds := &credentialSpy{creds: &oauth.ClientCredentials{ClientID: "old-client"}}
	ctx := WithAuthStores(context.Background(), AuthStores{KeychainTokens: keyTokens, KeychainCredentials: keyCreds})
	_, err := PersistOAuthLogin(ctx, cmdutil.AuthConfig{StorageBackend: "keychain", ProfileName: "test"}, oauth.ClientCredentials{ClientID: "new-client"}, &oauth.TokenSet{AccessToken: "new"})
	if err == nil || keyTokens.token.AccessToken != "old" || keyCreds.creds.ClientID != "old-client" {
		t.Fatal("failed token save split existing login pair")
	}
}

func TestFailedPairRollbackMustNotFallBack(t *testing.T) {
	keyTokens := &tokenSpy{saveErr: errors.New("keychain backend unavailable")}
	keyCreds := &credentialSpy{creds: &oauth.ClientCredentials{ClientID: "old-client"}, saveErrors: []error{nil, errors.New("rollback rejected")}}
	fileTokens, fileCreds := &tokenSpy{}, &credentialSpy{}
	ctx := WithAuthStores(context.Background(), AuthStores{KeychainTokens: keyTokens, KeychainCredentials: keyCreds, FileTokens: fileTokens, FileCredentials: fileCreds})
	_, err := PersistOAuthLogin(ctx, cmdutil.AuthConfig{StorageBackend: "auto", ProfileName: "test", AllowFileFallback: true}, oauth.ClientCredentials{ClientID: "new-client"}, &oauth.TokenSet{AccessToken: "new"})
	var rollbackErr *pairRollbackError
	if !errors.As(err, &rollbackErr) || fileTokens.saves != 0 || fileCreds.saves != 0 {
		t.Fatal("integrity error silently fell back to files")
	}
}

func TestAutoDoesNotHideExistingKeychainLoginWithFallback(t *testing.T) {
	keyTokens := &tokenSpy{token: &oauth.TokenSet{AccessToken: "old"}, saveErr: errors.New("keychain backend unavailable")}
	keyCreds := &credentialSpy{creds: &oauth.ClientCredentials{ClientID: "old-client"}}
	fileTokens, fileCreds := &tokenSpy{}, &credentialSpy{}
	ctx := WithAuthStores(context.Background(), AuthStores{KeychainTokens: keyTokens, KeychainCredentials: keyCreds, FileTokens: fileTokens, FileCredentials: fileCreds})
	_, err := PersistOAuthLogin(ctx, cmdutil.AuthConfig{StorageBackend: "auto", ProfileName: "test", AllowFileFallback: true}, oauth.ClientCredentials{ClientID: "new-client"}, &oauth.TokenSet{AccessToken: "new"})
	if err == nil || fileTokens.saves != 0 || fileCreds.saves != 0 || keyCreds.creds.ClientID != "old-client" {
		t.Fatal("auto reported a file login shadowed by stale keychain credentials")
	}
}
