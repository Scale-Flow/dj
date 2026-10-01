package cliutil

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/Scale-Flow/marten/pkg/cmdutil"
	"github.com/Scale-Flow/marten/pkg/oauth"
)

// AuthStores permits callers to supply storage implementations, including isolated
// stores for tests. A token and its client credentials always use one backend.
type AuthStores struct {
	KeychainTokens      oauth.Store
	FileTokens          oauth.Store
	KeychainCredentials oauth.ClientCredentialStore
	FileCredentials     oauth.ClientCredentialStore
}

type authStoresContextKey struct{}

func WithAuthStores(ctx context.Context, stores AuthStores) context.Context {
	return context.WithValue(ctx, authStoresContextKey{}, stores)
}

type authStorage struct {
	cfg    cmdutil.AuthConfig
	mode   cmdutil.CredentialBackend
	stores AuthStores
}

func newAuthStorage(ctx context.Context, cfg cmdutil.AuthConfig) (*authStorage, error) {
	mode := cmdutil.CredentialBackend(strings.ToLower(strings.TrimSpace(cfg.StorageBackend)))
	if mode == "" {
		mode = cmdutil.CredentialBackendAuto
	}
	if mode != cmdutil.CredentialBackendAuto && mode != cmdutil.CredentialBackendFile && mode != cmdutil.CredentialBackendKeychain {
		return nil, fmt.Errorf("unsupported oauth backend %q", cfg.StorageBackend)
	}
	stores, injected := ctx.Value(authStoresContextKey{}).(AuthStores)
	if !injected {
		if mode != cmdutil.CredentialBackendFile && cfg.ConfigDir != "" {
			stores.KeychainTokens = oauth.NewKeychainStore(cfg.ConfigDir)
			stores.KeychainCredentials = oauth.NewClientCredentialKeychainStore(cfg.ConfigDir)
		}
		if mode != cmdutil.CredentialBackendKeychain && cfg.OAuthStorePath != "" {
			stores.FileTokens = oauth.NewOAuthStore(cfg.OAuthStorePath)
			stores.FileCredentials = oauth.NewClientCredentialFileStore(oauth.ClientCredentialPathForTokenStore(cfg.OAuthStorePath))
		}
	}
	if cfg.OAuthKeychainStore != nil {
		stores.KeychainTokens = cfg.OAuthKeychainStore
	}
	if cfg.OAuthFileStore != nil {
		stores.FileTokens = cfg.OAuthFileStore
	}
	return &authStorage{cfg: cfg, mode: mode, stores: stores}, nil
}

func (s *authStorage) tokenStore(backend cmdutil.CredentialBackend) oauth.Store {
	if backend == cmdutil.CredentialBackendFile {
		return s.stores.FileTokens
	}
	return s.stores.KeychainTokens
}

func (s *authStorage) credentialStore(backend cmdutil.CredentialBackend) oauth.ClientCredentialStore {
	if backend == cmdutil.CredentialBackendFile {
		return s.stores.FileCredentials
	}
	return s.stores.KeychainCredentials
}

func (s *authStorage) loadToken(backend cmdutil.CredentialBackend) (*oauth.TokenSet, error) {
	store := s.tokenStore(backend)
	if store == nil {
		return nil, fmt.Errorf("%s backend unavailable", backend)
	}
	return store.Load(s.cfg.ProfileName)
}

// loadTokens is deliberately read-only: automatic migration would separate a
// token from the client credentials required to refresh it.
func (s *authStorage) loadTokens() (*oauth.TokenSet, cmdutil.CredentialBackend, error) {
	if s.mode != cmdutil.CredentialBackendAuto {
		ts, err := s.loadToken(s.mode)
		return ts, s.mode, err
	}
	if s.stores.KeychainTokens != nil {
		ts, err := s.loadToken(cmdutil.CredentialBackendKeychain)
		if err == nil {
			return ts, cmdutil.CredentialBackendKeychain, nil
		}
		if !errors.Is(err, oauth.ErrTokenNotFound) && !OAuthBackendUnavailable(err) {
			return nil, "", err
		}
	}
	if s.stores.FileTokens != nil && (s.cfg.AllowFileFallback || s.stores.KeychainTokens == nil) {
		ts, err := s.loadToken(cmdutil.CredentialBackendFile)
		return ts, cmdutil.CredentialBackendFile, err
	}
	return nil, "", oauth.ErrTokenNotFound
}

func (s *authStorage) loadCredentials(backend cmdutil.CredentialBackend) (*oauth.ClientCredentials, error) {
	store := s.credentialStore(backend)
	if store == nil {
		return nil, fmt.Errorf("%s client credential backend unavailable", backend)
	}
	creds, err := store.Load(s.cfg.ProfileName)
	if errors.Is(err, oauth.ErrClientCredentialsNotFound) {
		return nil, nil
	}
	return creds, err
}

// LoadOAuthStatus reads the chosen backend without migrating or refreshing.
func LoadOAuthStatus(ctx context.Context, cfg cmdutil.AuthConfig) (*oauth.TokenSet, *oauth.ClientCredentials, cmdutil.CredentialBackend, error) {
	s, err := newAuthStorage(ctx, cfg)
	if err != nil {
		return nil, nil, "", err
	}
	ts, source, err := s.loadTokens()
	if errors.Is(err, oauth.ErrTokenNotFound) {
		return nil, nil, "", nil
	}
	if err != nil {
		return nil, nil, "", err
	}
	creds, err := s.loadCredentials(source)
	return ts, creds, source, err
}

// LoadClientCredentials uses the existing token's backend. With no token yet,
// auto mode checks keychain then file; explicit modes never inspect the other.
func LoadClientCredentials(ctx context.Context, configDir, tokenPath, profile, selected string) (*oauth.ClientCredentials, error) {
	s, err := newAuthStorage(ctx, cmdutil.AuthConfig{ConfigDir: configDir, OAuthStorePath: tokenPath, ProfileName: profile, StorageBackend: selected, AllowFileFallback: true})
	if err != nil {
		return nil, err
	}
	if s.mode != cmdutil.CredentialBackendAuto {
		return s.loadCredentials(s.mode)
	}
	_, source, err := s.loadTokens()
	if err == nil {
		return s.loadCredentials(source)
	}
	if !errors.Is(err, oauth.ErrTokenNotFound) {
		return nil, err
	}
	if s.stores.KeychainCredentials != nil {
		creds, err := s.loadCredentials(cmdutil.CredentialBackendKeychain)
		if err == nil && creds != nil {
			return creds, nil
		}
		if err != nil && !OAuthBackendUnavailable(err) {
			return nil, err
		}
	}
	return s.loadCredentials(cmdutil.CredentialBackendFile)
}

// ResolveAuth keeps refresh tokens and client credentials on the selected
// backend, unlike marten's independent keychain-first credential lookup.
func ResolveAuth(ctx context.Context, cfg cmdutil.AuthConfig) (string, error) {
	if cfg.Strategy != "oauth2" {
		return cmdutil.ResolveAuth(ctx, cfg)
	}
	s, err := newAuthStorage(ctx, cfg)
	if err != nil {
		return "", err
	}
	ts, source, err := s.loadTokens()
	if err != nil {
		return "", fmt.Errorf("not authenticated; run: auth login: %w", err)
	}
	if ts == nil || ts.AccessToken == "" {
		return "", errors.New("not authenticated; run: auth login")
	}
	if ts.NeedsRefresh() && cfg.RefreshConfig != nil {
		refresh := *cfg.RefreshConfig
		creds, err := s.loadCredentials(source)
		if err != nil {
			return "", err
		}
		if creds != nil {
			// Do not combine a caller's different client ID with a stored secret.
			if refresh.ClientID == "" {
				refresh.ClientID = creds.ClientID
			}
			if refresh.ClientSecret == "" && refresh.ClientID == creds.ClientID {
				refresh.ClientSecret = creds.ClientSecret
			}
		}
		// Metadata is shared by legacy backends, so it must never supply client
		// credentials for a token. The selected credential store is authoritative.
		refreshed, refreshErr := oauth.Refresh(ctx, refresh, ts, oauth.Metadata{})
		if refreshErr != nil {
			if ts.IsExpired() {
				return "", fmt.Errorf("token expired and refresh failed: %w", refreshErr)
			}
		} else {
			if refreshed == nil || refreshed.AccessToken == "" {
				return "", errors.New("oauth refresh returned an invalid token")
			}
			if err := s.tokenStore(source).Save(cfg.ProfileName, *refreshed); err != nil {
				return "", err
			}
			if path := metadataPath(cfg); path != "" {
				_ = oauth.NewMetadataStore(path).Save(cfg.ProfileName, oauth.MergeMetadata(oauth.Metadata{}, refreshed, refresh.ClientID))
			}
			ts = refreshed
		}
	}
	if ts.IsExpired() {
		return "", errors.New("token expired; run: auth login")
	}
	return ts.AccessToken, nil
}

func metadataPath(cfg cmdutil.AuthConfig) string {
	if cfg.OAuthMetadataPath != "" {
		return cfg.OAuthMetadataPath
	}
	if cfg.OAuthStorePath == "" {
		return ""
	}
	return oauth.MetadataPathForTokenStore(cfg.OAuthStorePath)
}

// PersistOAuthLogin saves both halves of a login to the same backend. Only auto
// mode may fall back, and it falls back with the complete pair.
func PersistOAuthLogin(ctx context.Context, cfg cmdutil.AuthConfig, creds oauth.ClientCredentials, ts *oauth.TokenSet) (string, error) {
	if ts == nil || ts.AccessToken == "" || creds.ClientID == "" {
		return "", errors.New("invalid OAuth login credentials")
	}
	s, err := newAuthStorage(ctx, cfg)
	if err != nil {
		return "", err
	}
	backend := s.mode
	allowFallback := cfg.AllowFileFallback
	if backend == cmdutil.CredentialBackendAuto {
		_, source, loadErr := s.loadTokens()
		if loadErr == nil {
			backend = source
			// A surviving keychain login would shadow a newly saved file pair
			// on the next auto read. Require explicit file selection instead.
			if source == cmdutil.CredentialBackendKeychain {
				allowFallback = false
			}
		} else if errors.Is(loadErr, oauth.ErrTokenNotFound) {
			backend = cmdutil.CredentialBackendKeychain
		} else {
			return "", loadErr
		}
	}
	if err := s.savePair(backend, creds, ts); err != nil {
		var rollbackErr *pairRollbackError
		if errors.As(err, &rollbackErr) {
			return "", err
		}
		if s.mode != cmdutil.CredentialBackendAuto || backend != cmdutil.CredentialBackendKeychain || !allowFallback || !OAuthBackendUnavailable(err) {
			return "", err
		}
		backend = cmdutil.CredentialBackendFile
		if err := s.savePair(backend, creds, ts); err != nil {
			return "", err
		}
	}
	if path := metadataPath(cfg); path != "" {
		// Tokens carry lifecycle data and credentials carry the client ID. A
		// metadata write failure does not invalidate the successfully saved pair.
		_ = oauth.NewMetadataStore(path).Save(cfg.ProfileName, oauth.MergeMetadata(oauth.Metadata{}, ts, creds.ClientID))
	}
	return string(backend), nil
}

func (s *authStorage) savePair(backend cmdutil.CredentialBackend, creds oauth.ClientCredentials, ts *oauth.TokenSet) error {
	tokens, clients := s.tokenStore(backend), s.credentialStore(backend)
	if tokens == nil || clients == nil {
		return fmt.Errorf("%s backend unavailable", backend)
	}
	previous, err := clients.Load(s.cfg.ProfileName)
	if err != nil && !errors.Is(err, oauth.ErrClientCredentialsNotFound) {
		return err
	}
	if err := clients.Save(s.cfg.ProfileName, creds); err != nil {
		return err
	}
	if err := tokens.Save(s.cfg.ProfileName, *ts); err != nil {
		var rollbackErr error
		if previous == nil {
			rollbackErr = clients.Delete(s.cfg.ProfileName)
		} else {
			rollbackErr = clients.Save(s.cfg.ProfileName, *previous)
		}
		if rollbackErr != nil {
			// A failed rollback must never trigger silent fallback elsewhere.
			return &pairRollbackError{saveErr: err, rollbackErr: rollbackErr}
		}
		return err
	}
	return nil
}

type pairRollbackError struct {
	saveErr, rollbackErr error
}

func (e *pairRollbackError) Error() string {
	return fmt.Sprintf("OAuth login storage failed (%v); client credential rollback failed: %v", e.saveErr, e.rollbackErr)
}

func OAuthBackendUnavailable(err error) bool {
	if err == nil {
		return false
	}
	msg := strings.ToLower(err.Error())
	return strings.Contains(msg, "unsupported platform") ||
		strings.Contains(msg, "backend unavailable") ||
		strings.Contains(msg, "no credential backend available") ||
		strings.Contains(msg, "the name org.freedesktop.secrets was not provided by any .service files")
}
