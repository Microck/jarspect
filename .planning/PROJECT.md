# Jarspect

## What This Is

A multi-agent security scanner for game mods that detects malware before gamers install them. When a mod is uploaded, specialized agents analyze it from multiple angles — static code patterns, predicted runtime behavior, and author reputation — then synthesize a risk verdict with explanation. Built for the Microsoft AI Dev Days Hackathon 2026.

## Core Value

**Before gamers install a mod, 4 specialized agents analyze it for malware, providing a risk score and human-readable explanation of suspicious findings.**

## Requirements

### Validated

(None yet — ship to validate)

### Active

- [ ] Intake Agent that extracts mod files and identifies mod type
- [ ] Static Agent that decompiles and pattern matches suspicious code
- [ ] Behavior Agent that predicts runtime behavior from code analysis
- [ ] Reputation Agent that checks author history and community reports
- [ ] Verdict Agent that synthesizes risk score and explanation
- [ ] Web UI for mod upload and results display
- [ ] Known malware signature database (Azure AI Search)
- [ ] 2-minute demo video showing malware detection

### Out of Scope

- Multiple game platforms — Minecraft mods only for MVP
- Sandbox execution — static/behavioral prediction only
- Community reporting system — one-way scanning only
- Real-time Steam Workshop integration — file upload only
- Enterprise mod management — consumer focus

## Context

**Hackathon:** Microsoft AI Dev Days 2026 (Feb 10 - Mar 15, 2026)

**Target Prizes:**
- Primary: AI Apps & Agents ($20,000)
- Secondary: Enterprise ($10,000)

**Unique Intersection:**
- Gaming + Security = unexplored territory
- Real problem: Steam Workshop, Nexus Mods = malware vectors
- Consumer + Enterprise: Gamers AND game studios care

**Target Mod Type:** Minecraft .jar mods
- Most popular modding platform
- Java-based, decompilable
- Well-documented malware samples exist

## Constraints

- **Timeline**: 5 weeks (Feb 10 - Mar 15, 2026)
- **Tech Stack**: Rust, Axum, YARA-X, optional Azure integrations
- **Model Access**: Optional (heuristic-first verdict pipeline for deterministic runs)
- **Storage**: Azure Blob Storage (mods), Azure AI Search (signatures)
- **Decompilation**: Java decompilers for Minecraft mods
- **Demo**: 2-minute video required

## Key Decisions

| Decision | Rationale | Outcome |
|----------|-----------|---------|
| Minecraft only | Most popular, Java is decompilable | — Pending |
| 5 specialized agents | Clear analysis pipeline | — Pending |
| Prediction over sandbox | Simpler, faster for hackathon | — Pending |
| Conservative scoring | Avoid false positives on legitimate mods | — Pending |

---
*Last updated: 2026-02-08 after project initialization*
