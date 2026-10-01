package cliutil

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/Scale-Flow/marten/pkg/cmdutil"
	"github.com/Scale-Flow/marten/pkg/oauth"
	"github.com/Scale-Flow/marten/pkg/transport"
	"github.com/scale-flow/dj/internal/dj"
	"github.com/spf13/cobra"
)

// NewSpotifyClient resolves credentials only after validation, preview, and confirmation.
func NewSpotifyClient(cmd *cobra.Command, rctx *cmdutil.RuntimeContext) (*dj.Client, error) {
	dir := os.Getenv("XDG_CONFIG_HOME")
	if dir == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			return nil, fmt.Errorf("cannot determine home directory: %w", err)
		}
		dir = filepath.Join(home, ".config")
	}
	path := filepath.Join(dir, "dj", "oauth-tokens.json")
	token, err := ResolveAuth(cmd.Context(), cmdutil.AuthConfig{
		Strategy: "oauth2", StorageBackend: OAuthStorage(cmd), ConfigDir: "dj",
		ProfileName: rctx.ProfileName, AllowFileFallback: true,
		OAuthStorePath: path, OAuthMetadataPath: oauth.MetadataPathForTokenStore(path),
		RefreshConfig: &oauth.RefreshConfig{TokenURL: "https://accounts.spotify.com/api/token"},
	})
	if err != nil {
		return nil, err
	}
	return dj.NewClient(transport.NewClient(rctx.BaseURL, token, "Authorization", "Bearer "), rctx.Extra), nil
}
