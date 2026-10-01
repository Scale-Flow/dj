package cliutil

import (
	"github.com/Scale-Flow/marten/pkg/cmdutil"
	"github.com/spf13/cobra"
)

// OAuthStorage lets headless callers explicitly bypass an unavailable keychain.
func OAuthStorage(cmd *cobra.Command) string {
	if flag := cmd.Flag("auth-storage"); flag != nil {
		return flag.Value.String()
	}
	return "auto"
}

// ResolveSpotifyContext preserves explicit profile/env/flag overrides and supplies
// the service endpoint when a freshly authenticated profile has no config file.
func ResolveSpotifyContext(cmd *cobra.Command) (*cmdutil.RuntimeContext, error) {
	ctx, err := cmdutil.ResolveContext(cmd, "dj", "DJ")
	if err == nil && ctx.BaseURL == "" {
		ctx.BaseURL = "https://api.spotify.com"
	}
	return ctx, err
}
