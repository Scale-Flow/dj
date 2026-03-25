# Error Recovery

| Error | Cause | Fix |
|-------|-------|-----|
| `not authenticated — run: auth login` | No OAuth tokens stored | Run `dj auth login` with `DJ_CLIENT_ID` and `DJ_CLIENT_SECRET` set |
| `token expired — run: auth login` | Access token expired and refresh failed | Re-run `dj auth login`; ensure `DJ_CLIENT_ID` is set for auto-refresh |
| `DJ_CLIENT_ID environment variable not set` | Missing env var | `export DJ_CLIENT_ID=your_id` |
| `API error 403` | Free account trying playback control | Spotify Premium required for play/pause/next/previous |
| `API error 404` | Invalid track/album ID | Verify the Spotify ID is correct |
| `API error 429` | Rate limited | Wait for `Retry-After` seconds; rolling 30-second window |
| `API error 400` on play | Empty body or wrong param format | Use `--uris` for tracks, `--context-uri` for albums/playlists |
| `unsupported protocol scheme ""` | Base URL not configured | Create `~/.config/dj/config.yaml` with `profiles.default.base_url` |
| `redirect_uri: Not matching configuration` | Redirect URI mismatch in Spotify Dashboard | Add `http://127.0.0.1:8085/callback` to your app's redirect URIs |

## Exit Codes

| Code | Meaning |
|------|---------|
| 0 | Success |
| 1 | API error |
| 2 | Usage / validation error |
| 3 | Authentication error |
| 4 | Rate limited |
| 5 | Network error |
| 6 | Configuration error |
