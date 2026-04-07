---
name: dj
description: CLI tool for Spotify player control and music lookup CLI
---

# dj CLI Skill

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
