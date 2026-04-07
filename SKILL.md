---
name: dj
description: CLI tool for Spotify player control and music lookup CLI
---

# dj CLI Skill

## Install

Requires Go 1.26+:

```bash
go install github.com/scale-flow/dj/cmd/dj@latest
```

## Setup

1. Create a Spotify app at https://developer.spotify.com/dashboard
2. Run `dj auth login` and enter your Client ID and Secret when prompted
3. Authorize in the browser that opens

Tokens are stored in the OS keychain when available, falling back to `~/.config/dj/oauth-tokens.json`.

Run `dj auth status` to verify credentials are active.

## Available Commands
- `dj player now-playing` — Show the currently playing track
- `dj player status` — Show full playback state including device, shuffle, and repeat
- `dj player devices` — List available Spotify Connect devices
- `dj player play` — Start or resume playback (Premium required)
- `dj player pause` — Pause playback (Premium required)
- `dj player next` — Skip to next track (Premium required)
- `dj player previous` — Skip to previous track (Premium required)
- `dj tracks get` — Get a track by Spotify ID
- `dj albums get` — Get an album by Spotify ID
- `dj albums tracks` — List tracks on an album
- `dj search` — Search Spotify for tracks, albums, or artists

## Authentication

Run `dj auth login` to authenticate via OAuth2.

## Usage Notes

- All output is structured JSON on stdout.
- Use `--dry-run` to preview actions.
- Use `--yes` to skip confirmations.
- Use `--pretty` for human-readable output.
- Run `dj manifest` for machine-readable command discovery.
