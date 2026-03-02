# Roadmap: Jarspect (Milestone v2.0 "Logic rework")

## Overview

This milestone makes scan results reliable by switching from lossy string scanning to bytecode-native analysis, then rebuilding detectors, scoring, and behavior prediction around extracted evidence while keeping the existing API/UI flow intact.

## Phases

**Phase Numbering:**
- Integer phases (1, 2, 3): Planned milestone work
- Decimal phases (2.1, 2.2): Urgent insertions (marked with INSERTED)

- [ ] **Phase 1: Bytecode Evidence Core** - Extract bytecode facts (strings + invokes) into a stable, additive evidence schema.
- [ ] **Phase 2: Archive + YARA Fidelity** - Recursively scan jar-in-jar, parse metadata, and run YARA per-entry with correct severities.
- [ ] **Phase 3: Capability Detectors** - Detect real capability patterns from compiled bytecode with traceable evidence.
- [ ] **Phase 4: Scoring + Behavior Prediction** - Produce stable tiers (including CLEAN) with explainable synergy and evidence-derived predictions.
- [ ] **Phase 5: UI Verdict Rendering** - Display tiers and severities consistently in the web UI.
- [ ] **Phase 6: Regression Fixtures** - Ship safe fixtures + end-to-end tests that lock in the new logic and preserve demo behavior.

## Phase Details

### Phase 1: Bytecode Evidence Core
**Goal**: Scan output contains bytecode-native evidence (strings + resolved invokes) with location metadata, without breaking existing endpoints.
**Depends on**: Nothing (first phase)
**Requirements**: BYTE-01, BYTE-02, BYTE-03, API-01, EVID-01
**Success Criteria** (what must be TRUE):
  1. `/scan` results include constant-pool strings (Utf8 + string literals) extracted from `.class` files as explicit evidence.
  2. `/scan` results include resolved `invoke*` references as `(owner, name, descriptor)` plus location metadata (class, method, instruction offset when available).
  3. Strings constructed via `new String(new byte[]{...})` appear in findings as reconstructed strings (not placeholder/garbled evidence).
  4. Existing endpoints remain (`/upload`, `/scan`, `/scans/{scan_id}`) and any response changes are additive only.
**Plans**: TBD

### Phase 2: Archive + YARA Fidelity
**Goal**: The scan pipeline accurately understands archive structure (including nested jars) and produces entry-scoped YARA evidence with trustworthy severities.
**Depends on**: Phase 1
**Requirements**: ARCH-01, ARCH-02, YARA-01, YARA-02, YARA-03
**Success Criteria** (what must be TRUE):
  1. Scanning a jar containing an embedded jar produces findings originating from the embedded jar (with evidence showing the nested path) via recursive scanning.
  2. Scan output includes parsed mod metadata + manifest signals and flags inconsistencies / high-suspicion attributes as findings.
  3. YARA-X runs against each inflated archive entry (classes/resources), and YARA evidence references the specific entry path (not the jar blob).
  4. YARA indicators report severity derived from rule metadata (or defined conventions) and demo vs production rulepacks remain separated in reporting.
**Plans**: TBD

### Phase 3: Capability Detectors
**Goal**: The scan reliably detects real-world capability patterns from compiled bytecode with concrete evidence, not synthetic placeholders.
**Depends on**: Phase 2
**Requirements**: DETC-01, DETC-02, DETC-03, DETC-04, DETC-05, DETC-06, DETC-07, DETC-08
**Success Criteria** (what must be TRUE):
  1. Scan report flags execution primitives (`Runtime.exec`, `ProcessBuilder.start`) with resolved invoke evidence pointing to the callsites.
  2. Scan report flags outbound networking primitives and includes URL evidence when present in the bytecode-derived evidence set.
  3. Scan report flags dynamic loading and jar/filesystem modification patterns with evidence tied to the relevant classes/methods.
  4. Scan report flags persistence, unsafe deserialization, JNI/native loading, and credential/token theft indicators with traceable evidence.
**Plans**: TBD

### Phase 4: Scoring + Behavior Prediction
**Goal**: The verdict (tier + score) is stable, explainable, and driven by capability evidence, including evidence-derived behavior predictions.
**Depends on**: Phase 3
**Requirements**: SCOR-01, SCOR-02, SCOR-03, BEHV-01, BEHV-02
**Success Criteria** (what must be TRUE):
  1. A scan with no indicators returns tier `CLEAN` with score `0`.
  2. Scoring uses capability dedup + diminishing returns so repeated/duplicate signals do not inflate the score.
  3. Verdict explanation reports top contributing evidence and explicitly explains why capability combinations increased risk (synergy).
  4. Behavior prediction outputs URLs/commands/file writes derived from extracted evidence and includes confidence + rationale linking predictions to indicators.
**Plans**: TBD

### Phase 5: UI Verdict Rendering
**Goal**: The UI reflects the new tiers/severities consistently, including `CLEAN`, without confusing severity labels.
**Depends on**: Phase 4
**Requirements**: UI-01
**Success Criteria** (what must be TRUE):
  1. Web UI renders a `CLEAN` scan as `CLEAN` (not an error/empty state) and shows score `0` clearly.
  2. Web UI normalizes and displays severities consistently (e.g., `med` and `medium` do not diverge in presentation).
**Plans**: TBD

### Phase 6: Regression Fixtures
**Goal**: The new bytecode-first logic is protected by safe fixtures and end-to-end tests, and the existing demo flow still works.
**Depends on**: Phase 5
**Requirements**: TEST-01, TEST-02, TEST-03
**Success Criteria** (what must be TRUE):
  1. Safe, compiled fixtures exist such that scanning them fires each capability detector on bytecode-derived evidence (no mocks).
  2. An end-to-end scan test exercises `/scan` on a fixture jar and asserts expected indicators and tier outcomes.
  3. The demo sample still triggers demo signatures/rules so the existing demo flow remains intact.
**Plans**: TBD

## Progress

**Execution Order:**
Phases execute in numeric order: 1 -> 2 -> 3 -> 4 -> 5 -> 6

| Phase | Plans Complete | Status | Completed |
|-------|----------------|--------|-----------|
| 1. Bytecode Evidence Core | 0/TBD | Not started | - |
| 2. Archive + YARA Fidelity | 0/TBD | Not started | - |
| 3. Capability Detectors | 0/TBD | Not started | - |
| 4. Scoring + Behavior Prediction | 0/TBD | Not started | - |
| 5. UI Verdict Rendering | 0/TBD | Not started | - |
| 6. Regression Fixtures | 0/TBD | Not started | - |
