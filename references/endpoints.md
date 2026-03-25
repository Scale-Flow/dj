# Endpoint Reference

| Command | Method | Endpoint | Response | Notes |
|---------|--------|----------|----------|-------|
| `player now-playing` | GET | `/me/player/currently-playing` | NowPlaying | Artist/album nested in `item` |
| `player status` | GET | `/me/player` | PlaybackState | Superset of now-playing |
| `player devices` | GET | `/me/player/devices` | PlaybackDevice | Wrapped in `devices` key |
| `player play` | PUT | `/me/player/play` | 204 | Premium required |
| `player pause` | PUT | `/me/player/pause` | 204 | Premium required |
| `player next` | POST | `/me/player/next` | 204 | Premium required |
| `player previous` | POST | `/me/player/previous` | 204 | Premium required |
| `tracks get` | GET | `/tracks/{id}` | Track | No auth scope needed |
| `albums get` | GET | `/albums/{id}` | Album | No auth scope needed |
| `albums tracks` | GET | `/albums/{id}/tracks` | TrackSimplified[] | Paginated (offset) |
| `search` | GET | `/search` | Raw JSON | Polymorphic per-type paging |

## OAuth Scopes

| Scope | Commands |
|-------|----------|
| `user-read-currently-playing` | `player now-playing` |
| `user-read-playback-state` | `player status`, `player devices` |
| `user-modify-playback-state` | `player play`, `player pause`, `player next`, `player previous` |
