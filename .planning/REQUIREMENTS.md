# Requirements

## v1 Requirements

### Foundation (FOUND)

- [x] **FOUND-01**: Foundry project initialized
- [x] **FOUND-02**: File upload endpoint for mod files
- [x] **FOUND-03**: Mod extraction and type detection
- [x] **FOUND-04**: Azure Blob Storage for uploaded mods

### Static Analysis (STAT)

- [x] **STAT-01**: Intake Agent extracts .jar mod files
- [x] **STAT-02**: Static Agent decompiles Java classes
- [x] **STAT-03**: Static Agent pattern matches suspicious code
- [x] **STAT-04**: Known malware signature database in Azure AI Search
- [x] **STAT-05**: Suspicious pattern catalog (obfuscation, network calls, file writes)

### Behavior Analysis (BEH)

- [x] **BEH-01**: Behavior Agent analyzes decompiled code with LLM
- [x] **BEH-02**: Behavior Agent predicts file system access
- [x] **BEH-03**: Behavior Agent predicts network activity
- [x] **BEH-04**: Behavior Agent predicts startup/persistence behavior

### Reputation (REP)

- [x] **REP-01**: Reputation Agent looks up author history
- [x] **REP-02**: Reputation Agent checks for community reports
- [x] **REP-03**: Author age/activity scoring

### Verdict (VERD)

- [x] **VERD-01**: Verdict Agent synthesizes all findings
- [x] **VERD-02**: Risk score (LOW/MEDIUM/HIGH/CRITICAL)
- [x] **VERD-03**: Human-readable explanation of findings
- [x] **VERD-04**: Specific suspicious indicators listed

### Demo (DEMO)

- [x] **DEMO-01**: Web UI for mod upload
- [x] **DEMO-02**: Planted malware sample for demo
- [ ] **DEMO-03**: 2-minute video showing malware detection (manual follow-up)
- [x] **DEMO-04**: README with example scans

---

## v2 Requirements

### Enhancements

- [ ] Support for GTA V mods (.asi, .dll)
- [ ] Support for Unity mods (.dll)
- [ ] Community reporting integration
- [ ] Browser extension for Steam Workshop

---

## Out of Scope

- **Multiple game platforms** — Minecraft only for MVP
- **Sandbox execution** — prediction only, no execution
- **Real-time Workshop integration** — file upload only
- **Enterprise mod management** — consumer focus
- **False positive learning** — static rules only

---

## Traceability

| REQ-ID | Phase | Status | Success Criteria |
|--------|-------|--------|------------------|
| FOUND-01 | Phase 1: Foundation | Complete | Foundry project running |
| FOUND-02 | Phase 1: Foundation | Complete | File upload works |
| FOUND-03 | Phase 1: Foundation | Complete | Mod type detected correctly |
| FOUND-04 | Phase 1: Foundation | Complete | Files stored in Blob Storage |
| STAT-01 | Phase 2: Static | Complete | .jar files extracted |
| STAT-02 | Phase 2: Static | Complete | Java classes decompiled |
| STAT-03 | Phase 2: Static | Complete | Patterns detected |
| STAT-04 | Phase 2: Static | Complete | Signatures searchable |
| STAT-05 | Phase 2: Static | Complete | Catalog of 10+ patterns |
| BEH-01 | Phase 3: Behavior | Complete | LLM analyzes code |
| BEH-02 | Phase 3: Behavior | Complete | File access predicted |
| BEH-03 | Phase 3: Behavior | Complete | Network activity predicted |
| BEH-04 | Phase 3: Behavior | Complete | Persistence predicted |
| REP-01 | Phase 4: Reputation | Complete | Author history retrieved |
| REP-02 | Phase 4: Reputation | Complete | Community reports checked |
| REP-03 | Phase 4: Reputation | Complete | Author score calculated |
| VERD-01 | Phase 4: Reputation | Complete | Findings synthesized |
| VERD-02 | Phase 4: Reputation | Complete | Risk score assigned |
| VERD-03 | Phase 4: Reputation | Complete | Explanation generated |
| VERD-04 | Phase 4: Reputation | Complete | Indicators listed |
| DEMO-01 | Phase 5: Demo | Complete | Web UI functional |
| DEMO-02 | Phase 5: Demo | Complete | Malware sample ready |
| DEMO-03 | Phase 5: Demo | Manual follow-up | Video recorded |
| DEMO-04 | Phase 5: Demo | Complete | README complete |

**Coverage:** 24/24 requirements mapped (100%)
