# dj CLI — Agent Instructions

## How to Use This CLI

You are interacting with `dj`, a command-line tool that outputs structured JSON.

### Reading Output

- **stdout** contains JSON responses. Parse the `ok` field first.
- **stderr** contains human-readable status messages. Ignore in automation.
- Check `ok: true` for success, `ok: false` for errors.
- On error, read `error.code` for programmatic handling and `error.message` for context.

### Before Mutating

Always use `--dry-run` before mutating operations to verify the request:

```bash
dj <command> --dry-run [flags]
```

### Skipping Prompts

Mutating commands prompt for confirmation. Use `--yes` to bypass:

```bash
dj <command> --yes [flags]
```

### Discovery

Use the manifest command to discover all available commands:

```bash
dj manifest
```

### Error Handling

| Exit Code | Meaning | Action |
|-----------|---------|--------|
| 0 | Success | Parse `data` from response |
| 1 | API error | Check `error.code` and `error.message` |
| 2 | Usage error | Fix command arguments or flags |
| 3 | Auth error | Run `dj auth login` |
| 4 | Rate limited | Wait and retry |
| 5 | Network error | Check connectivity |
| 6 | Config error | Check profile configuration |
