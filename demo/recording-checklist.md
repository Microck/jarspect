# Demo Recording Checklist

Use this checklist when recording the 2-minute submission video.

## Pre-Recording Setup

- [ ] Ensure Rust toolchain is installed
- [ ] Start API server: `cargo run` (or `JARSPECT_BIND=127.0.0.1:8010 cargo run`)
- [ ] Open browser at `http://localhost:8000/`
- [ ] Open terminal in repo root
- [ ] Keep `demo/storyboard.md` visible for timing cues

## Recording Steps

- [ ] Show UI landing screen and quickly explain the problem
- [ ] Run `bash scripts/demo_run.sh` in terminal
- [ ] Show script output with `scan_id`, `risk_tier`, `risk_score`, indicators
- [ ] Return to UI and show verdict explanation + indicator cards
- [ ] Mention synthetic safety fixture (no real malware)
- [ ] Optionally show `GET /scans/{scan_id}` in docs or terminal

## Expected End State

- [ ] Demo run completes successfully
- [ ] Verdict appears as HIGH or CRITICAL for synthetic suspicious sample
- [ ] At least 3 indicators are visible (static, behavior, reputation)
- [ ] Recording is under 2:00 and follows storyboard flow

## Non-Blocking Follow-Up

- [ ] Export video to `demo/video.mp4` (manual step after implementation)
