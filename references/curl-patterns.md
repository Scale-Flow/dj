# curl Patterns

All patterns use `$TOKEN` from `dj auth status | jq -r '.data.token'`.

## Player

    # Now playing
    curl -s -H "Authorization: Bearer $TOKEN" \
      https://api.spotify.com/v1/me/player/currently-playing | jq

    # Resume
    curl -s -X PUT -H "Authorization: Bearer $TOKEN" \
      https://api.spotify.com/v1/me/player/play

    # Pause
    curl -s -X PUT -H "Authorization: Bearer $TOKEN" \
      https://api.spotify.com/v1/me/player/pause

    # Play specific track
    curl -s -X PUT -H "Authorization: Bearer $TOKEN" \
      -H "Content-Type: application/json" \
      -d '{"uris":["spotify:track:TRACK_ID"]}' \
      https://api.spotify.com/v1/me/player/play

## Search

    curl -s -H "Authorization: Bearer $TOKEN" \
      "https://api.spotify.com/v1/search?q=Bohemian+Rhapsody&type=track&limit=5" | jq

## Tracks & Albums

    curl -s -H "Authorization: Bearer $TOKEN" \
      https://api.spotify.com/v1/tracks/TRACK_ID | jq

    curl -s -H "Authorization: Bearer $TOKEN" \
      https://api.spotify.com/v1/albums/ALBUM_ID/tracks | jq
