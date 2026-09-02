# Autonomous Bug Bounty Triage & Severity Arbiter (`BugBountyArbiter`)

[![GenLayer Intelligent Contract](https://img.shields.io/badge/GenLayer-Intelligent%20Contract-8A2BE2.svg)](https://genlayer.com)
[![GenVM Runner](https://img.shields.io/badge/GenVM-py--genlayer%20v0.3.0--rc7-blue.svg)](https://github.com/genlayerlabs/genvm)
[![Python](https://img.shields.io/badge/Python-3.11%20%7C%203.12-blue.svg)](https://www.python.org/)
[![Tests](https://img.shields.io/badge/Tests-18%2F18%20Passing-brightgreen.svg)](tests/test_bounty_arbiter.py)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

A decentralized, autonomous Web3 security coordination primitive built for **GenLayer**. `BugBountyArbiter` automates vulnerability report intake, multi-validator AI-driven triage, severity arbitration, and on-chain payout settlement while maintaining strict state hygiene.

---

## 1. Overview & Problem Statement

In traditional Web2 and Web3 bug bounty programs (e.g. Immunefi, HackerOne), the vulnerability disclosure lifecycle depends entirely on centralized intermediaries or off-chain team multisigs:

- **Centralized Triage Bottlenecks**: Human triage queues take days or weeks, introducing communication lag and human error.
- **Subjective Disputes & Conflict of Interest**: Project teams often attempt to downgrade severity tiers (e.g. downgrading a Critical exploit to Low) to minimize payout liabilities.
- **Counterparty & Escrow Risk**: Security researchers must trust that a project team will honor their published policy and disburse rewards after private disclosure has already occurred.
- **Premature Exploit Exposure**: Vulnerability descriptions, reproduction steps, and proof-of-concept (PoC) code are passed through third-party platform databases, increasing the risk of leaked zero-days prior to patch deployment.

### How `BugBountyArbiter` Solves This

`BugBountyArbiter` removes the need for centralized arbiters by embedding autonomous multi-validator AI adjudication directly into an on-chain smart contract:
1. **Deterministic Scope Evaluation**: Vulnerability submissions are evaluated against an immutable, on-chain scope policy reference (`scope_policy_url`).
2. **Decentralized Multi-Validator Consensus**: GenLayer validators independently assess the validity and severity of the reported issue using GenVM's native LLM capabilities (`gl.nondet.exec_prompt`).
3. **Equivalence Principle Enforcement**: Consensus rules enforce strict agreement on vulnerability validity, reject hallucinated severity tiers, and prevent payout manipulation.
4. **Guaranteed On-Chain Settlement**: Once consensus finalizes a valid finding, bounty payouts are locked and claimable directly via contract execution, eliminating human dispute mediation.

---

## 2. Architecture & State Hygiene

A fundamental tenet of GenLayer intelligent contract design is balancing off-chain non-deterministic compute with lightweight on-chain state. 

```
┌────────────────────────────────────────────────────────────────────────┐
│               Ephemeral Non-Deterministic Execution                    │
│   (Leader & Validator memory only — NEVER persisted on-chain)          │
│                                                                        │
│  - Full vulnerability details & exploit steps                          │
│  - Raw LLM prompt inputs & complete chain-of-thought analysis          │
│  - Candidate JSON payload proposals                                    │
└──────────────────────────────────┬─────────────────────────────────────┘
                                   │ gl.vm.run_nondet_unsafe
                                   │ Consensus Finalization
                                   ▼
┌────────────────────────────────────────────────────────────────────────┐
│                     Permanent On-Chain Storage                         │
│                    (TreeMap[u256, Report])                             │
│                                                                        │
│  - id: u256                   - severity: str ("HIGH")                 │
│  - researcher: str            - rationale: str (truncated summary)     │
│  - target_component: str      - payout_due: u256                       │
│  - valid: bool                - claimed: bool                          │
└────────────────────────────────────────────────────────────────────────┘
```

### Key State Hygiene Rules
- **Zero Exploit Storage**: Raw exploit payloads and vulnerability descriptions (`vulnerability_details`) are **never** stored on-chain. Storing exploit code on a public ledger creates severe state bloat and leaks attack vectors before protocol teams can remediate the underlying codebase.
- **Sanitized Metadata Persistence**: Only the finalized adjudication results are written to `TreeMap[u256, Report]`.
- **Bounded Storage Footprints**: Rationale strings are length-capped (max 280 characters) to prevent unbounded gas consumption and denial-of-service via storage bloating.

### Storage Layout

```python
class BugBountyArbiter(gl.Contract):
    project_owner: str               # Authorized administrator address / identity
    scope_policy_url: str            # Canonical URL pointing to scope policy markdown
    is_active: bool                  # Program intake toggle (True = active, False = paused)
    total_submissions: u256          # Monotonically increasing submission counter
    payout_table: TreeMap[str, u256] # Standard tier reward lookup (NONE, LOW, MEDIUM, HIGH, CRITICAL)
    reports: TreeMap[u256, Report]   # Persisted sanitized report records keyed by report_id
```

### Stored Record Data Model

```python
@allow_storage
@dataclass
class Report:
    id: u256
    researcher: str
    target_component: str
    valid: bool
    severity: str
    rationale: str
    payout_due: u256
    claimed: bool
```

---

## 3. Consensus & Equivalence Principle Design

Because LLMs generate natural language non-deterministically, standard blockchain equality (`gl.eq_principle.strict_eq`) would fail across validators. Conversely, naive schema-only checks (which merely inspect whether the leader formatted JSON correctly) blindly trust the leader without running independent verification.

`BugBountyArbiter` implements a **Comparative Equivalence Principle** using `gl.vm.run_nondet_unsafe(leader_fn, validator_fn)`.

### Sequence Diagram

```mermaid
sequenceDiagram
    autonumber
    actor Researcher as Security Researcher
    participant Contract as BugBountyArbiter (GenVM)
    participant Leader as Leader Validator (LLM)
    participant Validators as Validator Network (LLM)
    actor Owner as Project Owner

    Researcher->>Contract: submit_report(researcher, target_component, details)
    activate Contract
    Contract->>Leader: leader_fn() -> gl.nondet.exec_prompt(LLM Triage)
    activate Leader
    Leader-->>Contract: Proposed Outcome: {valid, severity, rationale}
    deactivate Leader

    Contract->>Validators: validator_fn(leaders_res)
    activate Validators
    Validators->>Validators: 1. Verify schema integrity (valid, severity, rationale)
    Validators->>Validators: 2. Verify severity in standard tiers (reject hallucinations)
    Validators->>Validators: 3. Verify semantic coherence (not valid -> NONE severity)
    Validators->>Validators: 4. Rerun evaluation independently: val_payload = leader_fn()
    Validators->>Validators: 5. Enforce strict equality on valid boolean (leader_valid == val_valid)
    Validators->>Validators: 6. Enforce severity tier agreement (rank diff <= 1 tier tolerance)
    Validators-->>Contract: Consensus Decision (True = Approve / False = Reject)
    deactivate Validators

    alt Consensus Approved
        Contract->>Contract: Increment total_submissions & map payout_due
        Contract->>Contract: Store sanitized Report in reports[report_id]
        Contract-->>Researcher: Return new report_id
    else Consensus Rejected
        Contract-->>Researcher: Transaction Reverted (Round Rejected / Forced Rotation)
    end
    deactivate Contract

    Note over Researcher,Contract: Settlement Phase
    Researcher->>Contract: claim_payout(report_id)
    activate Contract
    Contract->>Contract: Gating: Check report exists, valid==True, claimed==False, payout>0
    Contract->>Contract: Set claimed = True
    Contract-->>Researcher: Return payout amount
    deactivate Contract
```

### Consensus & Equivalence Rule Matrix

| Check | Rule | Failure Consequence |
| :--- | :--- | :--- |
| **Execution State** | `isinstance(leaders_res, gl.vm.Return)` | Returns `False`: Leader crashed or encountered timeout. |
| **Payload Schema** | Dictionary with keys `"valid"`, `"severity"`, `"rationale"` | Returns `False`: Malformed JSON or corrupted return structure. |
| **Standard Tiers** | `leader_sev in {"NONE", "LOW", "MEDIUM", "HIGH", "CRITICAL"}` | Returns `False`: Rejects hallucinated tiers (e.g. `SUPER_CRITICAL`, `FATAL`). |
| **Semantic Coherence** | If `not valid` ➔ `severity == "NONE"`; If `valid` ➔ `severity != "NONE"` | Returns `False`: Rejects self-contradictory proposals. |
| **Independent Verification** | `val_payload = leader_fn()` | Returns `False`: Validator independently queries the model; cannot trust leader alone. |
| **Strict Validity Equality** | `leader_valid == val_valid` | Returns `False`: **Zero tolerance for validity disputes**. Both must agree report is valid. |
| **Severity Tier Bounding** | `abs(SEVERITY_RANKS[leader] - SEVERITY_RANKS[validator]) <= 1` | Returns `False`: Rejects major divergence (e.g. leader claims `CRITICAL` while validator assesses `LOW`). |

---

## 4. Contract Interface

The contract exposes 7 public methods (2 view methods and 5 write methods):

### Constructor

```python
def __init__(project_owner: str, scope_policy_url: str)
```
- `project_owner`: Administrator address or account string permitted to configure parameters.
- `scope_policy_url`: Public HTTP/HTTPS URL referencing the markdown scope policy (e.g. [SECURITY.md](SECURITY.md)).

### Methods

| Method | Type | Parameters | Returns | Description |
| :--- | :--- | :--- | :--- | :--- |
| `submit_report` | Write | `researcher: str`, `target_component: str`, `vulnerability_details: str` | `int` (report ID) | Ingests a vulnerability report. Triggers multi-validator LLM triage and equivalence verification. Persists sanitized outcome. |
| `claim_payout` | Write | `report_id: int` | `int` (payout amount) | Authorizes and claims payout for a verified valid report. Strictly gated against double-claims and invalid reports. |
| `get_report` | View | `report_id: int` | `dict` | Returns on-chain metadata for a submission (`id`, `researcher`, `target_component`, `valid`, `severity`, `rationale`, `payout_due`, `claimed`). |
| `get_program_status`| View | _None_ | `dict` | Returns program health: `project_owner`, `scope_policy_url`, `is_active`, `total_submissions`, and full `payout_table`. |
| `set_active` | Write | `is_active: bool` | `None` | (Admin-only) Toggles bounty program intake (allows pausing/unpausing submissions). |
| `update_payout` | Write | `severity: str`, `amount: int` | `None` | (Admin-only) Updates payout amounts for a standard severity tier (`LOW`, `MEDIUM`, `HIGH`, `CRITICAL`). |
| `update_scope_policy` | Write | `new_scope_url: str` | `None` | (Admin-only) Updates the referenced scope policy document URL. |

---

## 5. Local Development & Testing Guide

### Prerequisites
- Python 3.11 or 3.12
- `genvm-linter` (`pip install genvm-linter`)
- `genlayer-test` (`pip install genlayer-test pytest`)

### 1. Contract Linter Check
Validate SDK compliance, type annotations, storage rules, and AST safety:

```powershell
# Windows PowerShell
$env:PYTHONUTF8=1; genvm-lint check contracts/bounty_arbiter.py
```

Expected output:
```text
✓ Lint passed (3 checks)
✓ Validation passed
  Contract: BugBountyArbiter
  Methods: 7 (2 view, 5 write)
```

### 2. Run Test Suite
Run the 18 direct-mode and consensus mock tests with pytest:

```bash
pytest -v tests/test_bounty_arbiter.py
```

### Test Suite Breakdown (18/18 Passing)
```text
tests/test_bounty_arbiter.py::test_initialization_and_program_status PASSED      [  5%]
tests/test_bounty_arbiter.py::test_initialization_empty_owner_reverts PASSED     [ 11%]
tests/test_bounty_arbiter.py::test_initialization_empty_policy_url_reverts PASSED [ 16%]
tests/test_bounty_arbiter.py::test_submit_report_valid_critical PASSED           [ 22%]
tests/test_bounty_arbiter.py::test_submit_report_valid_tiers PASSED              [ 27%]
tests/test_bounty_arbiter.py::test_submit_report_invalid_spam PASSED             [ 33%]
tests/test_bounty_arbiter.py::test_validator_rejection_validity_disagreement PASSED [ 38%]
tests/test_bounty_arbiter.py::test_validator_rejection_hallucinated_severity_tier PASSED [ 44%]
tests/test_bounty_arbiter.py::test_validator_rejection_semantic_contradiction PASSED [ 50%]
tests/test_bounty_arbiter.py::test_validator_rejection_malformed_schema PASSED [ 55%]
tests/test_bounty_arbiter.py::test_validator_rejection_major_severity_divergence PASSED [ 61%]
tests/test_bounty_arbiter.py::test_claim_payout_flow PASSED                      [ 66%]
tests/test_bounty_arbiter.py::test_claim_payout_gating_double_claim_reverts PASSED [ 72%]
tests/test_bounty_arbiter.py::test_claim_payout_gating_invalid_report_reverts PASSED [ 77%]
tests/test_bounty_arbiter.py::test_claim_payout_nonexistent_report_reverts PASSED [ 83%]
tests/test_bounty_arbiter.py::test_submit_report_when_program_inactive_reverts PASSED [ 88%]
tests/test_bounty_arbiter.py::test_submit_report_input_validation PASSED         [ 94%]
tests/test_bounty_arbiter.py::test_administrative_methods_and_access_control PASSED [100%]

============================= 18 passed in 2.23s ==============================
```

---

## 6. Deployment & Interaction

### Deploying via GenLayer CLI
```bash
# Start local node
genlayer up

# Deploy BugBountyArbiter with owner and policy URL
genlayer deploy contracts/bounty_arbiter.py \
  --args '["0x2bd806c97F0e00aF1a1fC3328fA763a9269723C8", "https://raw.githubusercontent.com/JimmyOgb/bug-bounty-arbiter/main/SECURITY.md"]' \
  --network localnet
```

### Deploying via GenLayer Studio
1. Open [GenLayer Studio](https://studio.genlayer.com).
2. Load [`contracts/bounty_arbiter.py`](contracts/bounty_arbiter.py).
3. Specify constructor arguments:
   - `project_owner`: `0x2bd806c97F0e00aF1a1fC3328fA763a9269723C8`
   - `scope_policy_url`: `https://raw.githubusercontent.com/JimmyOgb/bug-bounty-arbiter/main/SECURITY.md`
4. Click **Deploy**. Use the interactive console to test report triage, view stored metadata, and test payout claims.

---

## 7. Security Policy

Refer to [`SECURITY.md`](SECURITY.md) for full program scope guidelines and component definitions.

---

## 8. License

This project is open-source software licensed under the [MIT License](LICENSE).
