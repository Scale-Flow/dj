package albums

import (
	"fmt"
	"net/url"
	"strconv"

	"github.com/Scale-Flow/marten/pkg/cmdutil"
	"github.com/Scale-Flow/marten/pkg/contract"
	"github.com/scale-flow/dj/internal/cli/cliutil"
	"github.com/scale-flow/dj/internal/dj"
	"github.com/spf13/cobra"
)

func newTracksCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "tracks",
		Short: "List tracks on an album",
		RunE:  runTracks,
	}
	cmd.Flags().String("market", "", "ISO 3166-1 alpha-2 country code")
	cmd.Flags().String("id", "", "Spotify album ID")
	_ = cmd.MarkFlagRequired("id")
	cmdutil.AddPaginationFlags(cmd)
	return cmd
}

func runTracks(cmd *cobra.Command, args []string) error {
	pf := cmdutil.GetPaginationFlags(cmd)
	if pf.Page < 1 {
		return cmdutil.WriteError(cmd, contract.ErrCodeValidation, "page must be at least 1")
	}
	if pf.PerPage < 1 || pf.PerPage > 50 {
		return cmdutil.WriteError(cmd, contract.ErrCodeValidation, "per-page must be between 1 and 50")
	}
	if pf.MaxPages < 1 {
		return cmdutil.WriteError(cmd, contract.ErrCodeValidation, "max-pages must be at least 1")
	}
	if pf.Page-1 > int(^uint(0)>>1)/pf.PerPage {
		return cmdutil.WriteError(cmd, contract.ErrCodeValidation, "page offset is too large")
	}

	rctx, err := cliutil.ResolveSpotifyContext(cmd)
	if err != nil {
		return cmdutil.WriteError(cmd, contract.ErrCodeConfig, err.Error())
	}
	flagMarket, _ := cmd.Flags().GetString("market")
	flagID, _ := cmd.Flags().GetString("id")
	builder := dj.NewClient(nil, rctx.Extra)
	path := builder.BuildPath("/v1/albums/{id}/tracks", map[string]string{"id": flagID})
	offset := (pf.Page - 1) * pf.PerPage
	// --all retains its documented whole-collection meaning, starting at page 1.
	if pf.All {
		offset = 0
	}
	requestPath := func(offset int) string {
		return path + dj.BuildQueryString(map[string]string{"market": flagMarket, "limit": strconv.Itoa(pf.PerPage), "offset": strconv.Itoa(offset)})
	}
	if cmdutil.DryRun(cmd) {
		return cmdutil.WriteDryRun(cmd, "GET", rctx.BaseURL+requestPath(offset), map[string]any{
			"paginated": true, "pagination_style": "offset", "all": pf.All,
			"limit": pf.PerPage, "offset": offset, "max_pages": pf.MaxPages,
		})
	}
	client, err := cliutil.NewSpotifyClient(cmd, rctx)
	if err != nil {
		return cmdutil.WriteError(cmd, contract.ErrCodeAuth, err.Error())
	}

	items := make([]dj.TrackSimplified, 0)
	var meta *contract.Pagination
	for fetched := 0; ; fetched++ {
		var page dj.Page[dj.TrackSimplified]
		if err := client.DoGet(cmd.Context(), requestPath(offset), &page); err != nil {
			return cliutil.WriteAPIError(cmd, err)
		}
		if page.Limit <= 0 || page.Offset < 0 || page.Total < 0 || page.Offset != offset {
			return cliutil.WriteAPIError(cmd, fmt.Errorf("invalid album tracks pagination: expected offset %d, got offset %d, limit %d, total %d", offset, page.Offset, page.Limit, page.Total))
		}
		totalPages := page.Total / page.Limit
		if page.Total%page.Limit != 0 {
			totalPages++
		}
		meta = &contract.Pagination{Page: page.Offset/page.Limit + 1, PerPage: page.Limit, TotalCount: page.Total, TotalPages: totalPages}
		items = append(items, page.Items...)
		if !pf.All || fetched+1 >= pf.MaxPages || len(page.Items) == 0 {
			break
		}
		next, more, err := nextTracksOffset(page)
		if err != nil {
			return cliutil.WriteAPIError(cmd, err)
		}
		if !more {
			break
		}
		offset = next
	}
	return cmdutil.WriteList(cmd, items, contract.Meta{Pagination: meta})
}

func nextTracksOffset(page dj.Page[dj.TrackSimplified]) (int, bool, error) {
	// Spotify's next URL supplies the continuation position. Rebuild the request
	// against our own endpoint instead of forwarding credentials to that URL.
	if page.Next != nil && *page.Next != "" {
		nextURL, err := url.Parse(*page.Next)
		if err != nil {
			return 0, false, fmt.Errorf("invalid album tracks next URL: %w", err)
		}
		next, err := strconv.Atoi(nextURL.Query().Get("offset"))
		if err != nil || next <= page.Offset {
			return 0, false, fmt.Errorf("invalid album tracks next offset")
		}
		return next, true, nil
	}
	// Total also permits traversal when a compatible API omits next links.
	if page.Total-page.Offset > page.Limit {
		return page.Offset + page.Limit, true, nil
	}
	return 0, false, nil
}
