# Requirements: Jarspect

**Defined:** 2026-03-02
**Core Value:** Upload a `.jar`, get a risk verdict with explainable indicators before you install.

## v1 Requirements

Requirements for milestone v2.0 "Logic rework". Each maps to roadmap phases.

### Bytecode Analysis

- [ ] **BYTE-01**: Scan extracts constant-pool strings from `.class` files (Utf8 + string literals)
- [ ] **BYTE-02**: Scan resolves `invoke*` bytecode instructions to `(owner, name, descriptor)` method refs
- [ ] **BYTE-03**: Scan reconstructs strings built via `new String(new byte[]{...})` and includes them as evidence

### Capability Detectors

- [ ] **DETC-01**: Scan detects process execution primitives in compiled bytecode (`Runtime.exec`, `ProcessBuilder.start`)
- [ ] **DETC-02**: Scan detects outbound networking primitives in compiled bytecode (URL/HTTP APIs) and reports URL evidence when present
- [ ] **DETC-03**: Scan detects dynamic code loading primitives (`URLClassLoader`, `defineClass`, reflective invoke chains)
- [ ] **DETC-04**: Scan detects jar/filesystem modification patterns (zip/jar output streams, directory traversal + writes)
- [ ] **DETC-05**: Scan detects persistence indicators (Windows Run key/systemd/schtasks/cron markers and correlated exec)
- [ ] **DETC-06**: Scan detects unsafe deserialization sinks (`ObjectInputStream.readObject`) and labels as vulnerability-risk
- [ ] **DETC-07**: Scan detects JNI/native library loading (`System.load/loadLibrary`, embedded `.dll/.so/.dylib`)
- [ ] **DETC-08**: Scan detects credential/token theft indicators (Discord/browser/Minecraft session access markers)

### Archive & Metadata

- [ ] **ARCH-01**: Scan detects nested jars (jar-in-jar) and recursively scans embedded jars
- [ ] **ARCH-02**: Scan parses mod metadata + manifest signals and reports inconsistencies and high-suspicion attributes

### YARA

- [ ] **YARA-01**: YARA-X scans each inflated archive entry (class/resources), not the jar blob
- [ ] **YARA-02**: YARA indicators carry correct severity derived from rule metadata (or defined conventions)
- [ ] **YARA-03**: Demo and production rulepacks are kept separate to avoid mixing fake demo IOCs with real detections

### Scoring & Verdict

- [ ] **SCOR-01**: Verdict supports `CLEAN` tier (score 0 with no indicators)
- [ ] **SCOR-02**: Scoring uses a capability+synergy model with dedup and diminishing returns (prevents score inflation)
- [ ] **SCOR-03**: Verdict explanation reports top contributing evidence and why combinations increased risk

### Behavior Prediction

- [ ] **BEHV-01**: Behavior prediction derives URLs/commands/file writes from extracted evidence (no hardcoded placeholder evidence)
- [ ] **BEHV-02**: Behavior prediction includes confidence and traceable rationale linking predictions to indicators

### API & Evidence Schema

- [ ] **API-01**: Existing endpoints remain (`/upload`, `/scan`, `/scans/{scan_id}`); response changes are additive only
- [ ] **EVID-01**: Bytecode findings include location metadata (class name, method name, and instruction offset when available)

### UI

- [ ] **UI-01**: Web UI displays `CLEAN` tier correctly and normalizes severities consistently (`med` vs `medium`)

### Verification & Regression Tests

- [ ] **TEST-01**: Test suite includes safe fixtures proving each detector can fire on compiled bytecode (no mocks)
- [ ] **TEST-02**: End-to-end scan test proves a fixture jar produces expected indicators and tier outcomes
- [ ] **TEST-03**: Demo sample still triggers demo signatures/rules (keeps existing demo flow intact)

## v2 Requirements

Deferred to a future milestone (tracked but not in this roadmap).

### Product Extensions

- **CLIS-01**: Provide a CLI interface (scan local jar paths and print JSON + summary)
- **TINT-01**: Threat intel integration (online reputation lookups)
- **HOST-01**: Hosted scanning service / multi-tenant deployment

## Out of Scope

| Feature | Reason |
|---------|--------|
| Dynamic/sandboxed execution of untrusted code | Safety + high complexity; static analysis only for now |
| Real malware corpus shipped in-repo | Safety and distribution concerns; use safe synthetic fixtures |
| Cloud hosted scanning | Keep single local binary until core engine is solid |

## Traceability

Which phases cover which requirements. Populated during roadmap creation.

| Requirement | Phase | Status |
|-------------|-------|--------|
| BYTE-01 | Phase 1 | Pending |
| BYTE-02 | Phase 1 | Pending |
| BYTE-03 | Phase 1 | Pending |
| DETC-01 | Phase 3 | Pending |
| DETC-02 | Phase 3 | Pending |
| DETC-03 | Phase 3 | Pending |
| DETC-04 | Phase 3 | Pending |
| DETC-05 | Phase 3 | Pending |
| DETC-06 | Phase 3 | Pending |
| DETC-07 | Phase 3 | Pending |
| DETC-08 | Phase 3 | Pending |
| ARCH-01 | Phase 2 | Pending |
| ARCH-02 | Phase 2 | Pending |
| YARA-01 | Phase 2 | Pending |
| YARA-02 | Phase 2 | Pending |
| YARA-03 | Phase 2 | Pending |
| SCOR-01 | Phase 4 | Pending |
| SCOR-02 | Phase 4 | Pending |
| SCOR-03 | Phase 4 | Pending |
| BEHV-01 | Phase 4 | Pending |
| BEHV-02 | Phase 4 | Pending |
| API-01 | Phase 1 | Pending |
| EVID-01 | Phase 1 | Pending |
| UI-01 | Phase 5 | Pending |
| TEST-01 | Phase 6 | Pending |
| TEST-02 | Phase 6 | Pending |
| TEST-03 | Phase 6 | Pending |

**Coverage:**
- v1 requirements: 28 total
- Mapped to phases: 28
- Unmapped: 0

---
*Requirements defined: 2026-03-02*
*Last updated: 2026-03-02 after initial definition*
