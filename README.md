worm-scan
=========

A zero-dependency Node v22 CLI that scans your current project's installed npm packages against a malware version list and flags critical and adjacent versions.

What it does
- Fetches malware data from `https://malware-list.aikido.dev/malware_predictions.json`.
- Runs `npm ls --all --json` in the current directory (or uses a JSON fixture via env var).
- Flags Critical when there’s an exact `x.y.z` match.
- Flags Warning when same major.minor and patch within ±1 (configurable).
- Exit codes: 2 on criticals, 0 otherwise; 1 on tool errors.

Install (global)
- From this repo: `npm install -g .` (or `npm link`)

Update (global)
- From this repo again: `npm install -g .`

Run
- `worm-scan`
- Or: `npm exec --location=global worm-scan`

Environment test hooks (tests only; do not use in prod)
- `WORMSCAN_DATA_URL` — override malware list URL (http/https or file:// URL).
- `WORMSCAN_NPM_LS_JSON` — path to an `npm ls --all --json` output file to bypass spawning npm.
- `WORMSCAN_PATCH_DISTANCE` — integer (default 1) controlling warning window.

Notes
- `npm ls` can return non‑zero for peer conflicts; worm-scan still parses stdout.
- Output is deterministic, with ANSI colors for emphasis (honors `NO_COLOR`).

Developing & Testing
- Requires Node 22+.
- Run tests: `node --test`

Exit codes
- 0: No criticals (warnings may be present)
- 1: Tool error (network failure, invalid JSON, etc.)
- 2: One or more critical findings

Troubleshooting
- If network is blocked, set `WORMSCAN_DATA_URL` to a local test server or fixture.
- If your project has complex peer dependency warnings, consider capturing `npm ls --all --json` into a file and setting `WORMSCAN_NPM_LS_JSON` to that path.
