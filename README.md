# Autonomous Bug Bounty Triage & Severity Arbiter (`BugBountyArbiter`)

[![GenLayer Intelligent Contract](https://img.shields.io/badge/GenLayer-Intelligent%20Contract-8A2BE2.svg)](https://genlayer.com)
[![GenVM Runner](https://img.shields.io/badge/GenVM-py--genlayer%20v0.3.0--rc7-blue.svg)](https://github.com/genlayerlabs/genvm)
[![Python](https://img.shields.io/badge/Python-3.11%20%7C%203.12-blue.svg)](https://www.python.org/)
[![Tests](https://img.shields.io/badge/Tests-31%2F31%20Passing-brightgreen.svg)](tests/test_bounty_arbiter.py)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

A decentralized, autonomous Web3 security coordination primitive and **adjudication oracle** built for **GenLayer**. `BugBountyArbiter` automates vulnerability report intake with authenticated submitter binding (`msg.sender`), robust parsed origin and path-boundary URL validation, dual-fetch fail-closed multi-validator AI triage, exact severity consensus arbitration, and certified on-chain adjudication metadata generation for downstream escrows, vaults, and DAOs.

---

## 1. Overview & Problem Statement

In traditional Web2 and Web3 bug bounty programs (e.g. Immunefi, HackerOne), the vulnerability disclosure lifecycle depends entirely on centralized intermediaries or off-chain team multisigs:

- **Centralized Triage Bottlenecks**: Human triage queues take days or weeks, introducing communication lag and human error.
- **Subjective Disputes & Conflict of Interest**: Project teams often attempt to downgrade severity tiers (e.g. downgrading a Critical exploit to Low) to minimize payout liabilities.
- **Counterparty & Escrow Risk**: Security researchers must trust that a project team will honor their published policy and disburse rewards after private disclosure has already occurred.
- **Subjective Narrative Risk**: Relying purely on an arbitrary submitter's narrative without independently acquired target source code or verifiable proof risks approving phantom claims or hallucinated payouts.
- **Vulnerable Claim Paths & Hollow Balances**: Storing hollow on-chain claims without authenticated researcher binding or unbacked token balances creates systemic security risks.

### How `BugBountyArbiter` Solves This

`BugBountyArbiter` implements a robust, fail-closed on-chain adjudication protocol:
1. **Authenticated Submitter Binding**: Submissions automatically bind directly to the transaction caller (`researcher: Address = gl.message.sender`). The caller cannot spoof researcher addresses or manipulate identity parameters.
2. **Robust Parsed Origin & Path-Boundary Validation**: Replaces naive string prefix checks with structural URL parsing (`urllib.parse.urlsplit`):
   - Enforces `scheme == "https"`.
   - Enforces exact host match against authoritative domains (e.g. `raw.githubusercontent.com`).
   - Enforces path prefix boundary checking by path segments, strictly preventing lookalike repo names (e.g. `bug-bounty-arbiter-fake`).
   - Rejects query strings, embedded credentials/userinfo, and path traversal elements (`..`).
   - Applies validation across both `scope_policy_url` and `target_evidence_url`.
3. **Dual-Fetch Fail-Closed Acquisition**: Inside consensus, both leader and validators MUST successfully fetch both the authoritative scope policy AND the authoritative target source/evidence via `gl.nondet.web.get`. If either URL fails (HTTP non-200, empty body, or connection error), the contract **fails closed** immediately (`gl.vm.UserError`). Under NO circumstance can LLM adjudication proceed without live, authoritative ground truth.
4. **Decentralized Multi-Validator Consensus**: GenLayer validators independently triage the vulnerability against the retrieved policy and target evidence using GenVM's native LLM capabilities (`gl.nondet.exec_prompt`).
5. **Strict Severity Equivalence (Exact Binding)**: Because severity tier directly indexes into `payout_table` (`recommended_payout_units`), validators MUST independently agree on the **exact severity tier** (`LOW`, `MEDIUM`, `HIGH`, `CRITICAL`, `NONE`) and the exact `valid` boolean. Adjacent tier drift is strictly rejected.
6. **Oracle Primitive & Adjudication Metadata**: The contract functions as a clean oracle primitive. Verified findings are permanently certified as immutable adjudication metadata (`ReportMetadata`), allowing downstream vaults, automated escrows, or governance DAOs to read and execute settlements with verified security guarantees.

---

## 2. Architecture & State Hygiene

A fundamental tenet of GenLayer intelligent contract design is balancing off-chain non-deterministic compute with lightweight on-chain state.

```
┌────────────────────────────────────────────────────────────────────────┐
│               Ephemeral Non-Deterministic Execution                    │
│   (Leader & Validator memory only — NEVER persisted on-chain)          │
│                                                                        │
│  - Full vulnerability details & exploit reproduction steps             │
│  - Authoritative target code & scope policy text fetched via web       │
│  - Raw LLM prompt inputs & complete chain-of-thought analysis          │
│  - Candidate JSON payload proposals                                    │
└──────────────────────────────────┬─────────────────────────────────────┘
                                   │ gl.vm.run_nondet
                                   │ Consensus Finalization
                                   ▼
┌────────────────────────────────────────────────────────────────────────┐
│                     Permanent On-Chain Storage                         │
│                 (TreeMap[u256, ReportMetadata])                        │
│                                                                        │
│  - id: u256                       - severity: str ("HIGH")             │
│  - researcher: Address            - rationale: str (truncated summary) │
│  - target_evidence_url: str       - recommended_payout_units: u256     │
│  - valid: bool                                                         │
└────────────────────────────────────────────────────────────────────────┘
```

### Key State Hygiene Rules
- **Zero Exploit Storage**: Raw exploit payloads and vulnerability descriptions (`vulnerability_details`) are **never** persisted on-chain. Storing exploit code on a public ledger creates severe state bloat and leaks attack vectors before protocol teams can remediate the codebase.
- **Sanitized Metadata Persistence**: Only the finalized adjudication results are written to `TreeMap[u256, ReportMetadata]`.
- **Bounded Storage Footprints**: Rationale strings are length-capped (max 280 characters) to prevent unbounded storage bloating.
- **No Hollow Claims**: Instead of simulating hollow payouts without funded balances, verdicts are exposed as certified adjudication metadata for consumption by dedicated on-chain treasury vaults or escrows.

### Storage Layout

```python
class BugBountyArbiter(gl.Contract):
    project_owner: str                      # Authorized administrator address
    scope_policy_url: str                   # Validated HTTPS URL to scope policy markdown
    authoritative_target_prefix: str        # Validated HTTPS prefix defining domain boundary
    is_active: bool                         # Program intake toggle (True = active, False = paused)
    total_submissions: u256                 # Monotonically increasing submission counter
    payout_table: TreeMap[str, u256]        # Standard tier reward recommendation lookup
    reports: TreeMap[u256, ReportMetadata]  # Persisted sanitized adjudication records
```

### Stored Record Data Model

```python
@allow_storage
@dataclass
class ReportMetadata:
    id: u256
    researcher: Address
    target_evidence_url: str
    valid: bool
    severity: str
    rationale: str
    recommended_payout_units: u256
```

---

## 3. Consensus & Equivalence Principle Design

Because LLMs generate natural language non-deterministically, standard blockchain equality (`gl.eq_principle.strict_eq`) would fail across validators. Conversely, naive schema-only checks blindly trust the leader without running independent verification.

`BugBountyArbiter` implements a **Comparative Equivalence Principle** using `gl.vm.run_nondet(leader_fn, validator_fn)` combined with **Dual-Fetch Fail-Closed Web Acquisition**, **Parsed Origin and Path-Boundary Validation**, and **Strict Severity Equivalence**:

1. **Parsed Origin & Path-Boundary Validation**: Prior to consensus execution and inside validator checks, the contract parses the target evidence URL and validates:
   - `scheme == "https"`
   - Exact host match against `authoritative_target_prefix` host
   - Strict path segment boundary matching against the prefix path root
   - Rejection of query strings, userinfo/credentials, and path traversal (`..`)
2. **Dual-Fetch Fail-Closed Acquisition**: Inside `leader_fn` and independently inside `validator_fn`:
   - Scope policy is fetched via `gl.nondet.web.get(self.scope_policy_url)`.
   - Target evidence is fetched via `gl.nondet.web.get(target_evidence_url)`.
   - If either request returns non-200 or an empty body, execution reverts with `gl.vm.UserError("Failed to acquire authoritative scope policy or target evidence; failing closed.")`.
3. **Objective LLM Verification**: The evaluation prompt feeds the fetched policy text, the fetched target evidence/code, and the researcher's reproduction steps. The LLM verifies whether the fetched evidence objectively demonstrates the claimed exploit against the fetched policy.
4. **Exact Severity Binding**: Because the severity tier directly indexes into `self.payout_table` (`recommended_payout_units`), loose tolerances (such as adjacent severity allowances) are strictly rejected. If `leader_data["severity"] != my_eval["severity"]` or `leader_data["valid"] != my_eval["valid"]`, `validator_fn` returns `False`. Consensus is only achieved when both leader and validator independently arrive at the exact same severity tier and validity decision.

### Sequence Diagram

```mermaid
sequenceDiagram
    autonumber
    actor Researcher as Security Researcher (msg.sender)
    participant Contract as BugBountyArbiter (GenVM)
    participant Web as Authoritative Web (gl.nondet.web.get)
    participant Leader as Leader Validator (LLM)
    participant Validators as Validator Network (LLM)
    actor Downstream as Downstream Vault / Escrow / DAO

    Researcher->>Contract: submit_report(evidence_url, details)
    activate Contract
    Contract->>Contract: Bind researcher = gl.message.sender
    Contract->>Contract: Validate parsed origin & path boundary on evidence_url
    Contract->>Leader: leader_fn()
    activate Leader
    Leader->>Web: gl.nondet.web.get(scope_policy_url)
    Web-->>Leader: Scope Policy Response (status 200, non-empty)
    Leader->>Web: gl.nondet.web.get(evidence_url)
    Web-->>Leader: Authoritative Target Evidence (status 200, non-empty)
    Note over Leader: If either fetch fails/empty -> FAIL CLOSED (revert)
    Leader->>Leader: gl.nondet.exec_prompt(Policy + Target Evidence + Submission)
    Leader-->>Contract: Proposed Outcome: {valid, severity, rationale}
    deactivate Leader

    Contract->>Validators: validator_fn(leaders_res)
    activate Validators
    Validators->>Validators: 1. Verify schema & standard tiers
    Validators->>Validators: 2. Validate parsed origin & path boundary on evidence_url
    Validators->>Web: Independent fetch of scope_policy_url & evidence_url
    Web-->>Validators: Scope Policy & Evidence payloads
    Note over Validators: If either fetch fails/empty -> FAIL CLOSED
    Validators->>Validators: 3. Rerun independent evaluation: val_payload = leader_fn()
    Validators->>Validators: 4. Enforce strict equality on valid boolean (leader_valid == val_valid)
    Validators->>Validators: 5. Enforce EXACT severity tier agreement (leader_sev == val_sev)
    Validators-->>Contract: Consensus Decision (True = Agree / False = Reject)
    deactivate Validators

    alt Consensus Approved
        Contract->>Contract: Increment total_submissions & map recommended_payout_units
        Contract->>Contract: Store ReportMetadata in reports[report_id]
        Contract-->>Researcher: Return new report_id
    else Consensus Rejected
        Contract-->>Researcher: Transaction Reverted (Forced Rotation / Reject)
    end
    deactivate Contract

    Note over Downstream,Contract: Downstream Oracle Consumption Phase
    Downstream->>Contract: get_adjudicated_report(report_id)
    activate Contract
    Contract-->>Downstream: Return certified ReportMetadata (researcher, severity, units)
    deactivate Contract
    Downstream->>Downstream: Execute programmatic escrow/vault disbursement to researcher
```

### Consensus & Equivalence Rule Matrix

| Check | Rule | Failure Consequence |
| :--- | :--- | :--- |
| **Authenticated Sender Binding** | `researcher = gl.message.sender` | Cryptographically binds report to transaction sender. Prevents address spoofing. |
| **Parsed Origin Gating** | `url_parsed.scheme == "https"` & `url_parsed.hostname == prefix_parsed.hostname` | Reverts: `Evidence URL violates authoritative domain boundary: hostname mismatch`. |
| **Path Boundary Checking** | `url_segments[:len(prefix_segments)] == prefix_segments` | Reverts: `Evidence URL violates authoritative domain boundary: path prefix mismatch`. |
| **Payload Cleanliness** | No query strings, userinfo/credentials, or `..` path traversal | Reverts: `Evidence URL violates authoritative domain boundary: ... not permitted`. |
| **Execution State** | `isinstance(leaders_res, gl.vm.Return)` | Returns `False`: Leader crashed or encountered timeout. |
| **Payload Schema** | Dictionary with keys `"valid"`, `"severity"`, `"rationale"` | Returns `False`: Malformed JSON or corrupted return structure. |
| **Standard Tiers** | `leader_sev in {"NONE", "LOW", "MEDIUM", "HIGH", "CRITICAL"}` | Returns `False`: Rejects hallucinated tiers (e.g. `SUPER_CRITICAL`, `FATAL`). |
| **Semantic Coherence** | If `not valid` ➔ `severity == "NONE"`; If `valid` ➔ `severity != "NONE"` | Returns `False`: Rejects self-contradictory proposals. |
| **Dual Web Acquisition** | `policy_res.status == 200` & `evidence_res.status == 200` & bodies non-empty | Reverts: `Failed to acquire authoritative scope policy or target evidence; failing closed.` |
| **Independent Verification** | `val_payload = leader_fn()` | Returns `False`: Validator independently executes web retrieval and LLM prompt. |
| **Strict Validity Equality** | `leader_valid == val_valid` | Returns `False`: **Zero tolerance for validity disputes**. Both must agree report is valid. |
| **Exact Severity Equivalence**| `leader_sev == val_sev` | Returns `False`: **Zero tolerance for severity mismatches**. Binds exact recommended units. |

---

## 4. Contract Interface

The contract exposes 8 public methods (3 view methods and 5 write methods):

### Constructor

```python
def __init__(
    project_owner: str,
    scope_policy_url: str,
    authoritative_target_prefix: str,
)
```
- `project_owner`: Administrator address permitted to configure parameters.
- `scope_policy_url`: Validated HTTPS URL referencing the markdown scope policy (e.g. [SECURITY.md](SECURITY.md)).
- `authoritative_target_prefix`: Validated HTTPS prefix defining the authoritative domain and path boundary.

### Methods

| Method | Type | Parameters | Returns | Description |
| :--- | :--- | :--- | :--- | :--- |
| `submit_report` | Write | `target_evidence_url: str`, `vulnerability_details: str` | `int` (report ID) | Ingests a report bound to `msg.sender`. Validates parsed origin and path boundary, fetches live policy & evidence, fails closed on any fetch failure, runs multi-validator LLM triage, and enforces exact severity equivalence. |
| `get_adjudicated_report` | View | `report_id: u256` | `ReportMetadata` | Returns certified adjudication metadata (`id`, `researcher: Address`, `target_evidence_url`, `valid`, `severity`, `rationale`, `recommended_payout_units`) for downstream oracle consumers. |
| `get_report` | View | `report_id: u256` | `dict` | Returns serialized on-chain metadata dictionary for a submission. |
| `get_program_status`| View | _None_ | `dict` | Returns program health: `project_owner`, `scope_policy_url`, `authoritative_target_prefix`, `is_active`, `total_submissions`, and `payout_table`. |
| `set_active` | Write | `is_active: bool` | `None` | (Admin-only) Toggles bounty program intake (allows pausing/unpausing submissions). |
| `update_payout` | Write | `severity: str`, `amount: int` | `None` | (Admin-only) Updates payout recommendation units for a standard severity tier. |
| `update_scope_policy` | Write | `new_scope_url: str` | `None` | (Admin-only) Updates the referenced scope policy document URL after URL validation. |
| `update_authoritative_target_prefix` | Write | `new_prefix: str` | `None` | (Admin-only) Updates the authoritative target domain boundary prefix after URL validation. |

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
$env:PYTHONIOENCODING="utf-8"; genvm-lint check contracts/bounty_arbiter.py
```

Expected output:
```text
✓ Lint passed (3 checks)
✓ Validation passed
  Contract: BugBountyArbiter
  Methods: 8 (3 view, 5 write)
```

### 2. Run Test Suite
Run the comprehensive test suite with pytest:

```bash
pytest -v tests/test_bounty_arbiter.py
```

### Test Suite Breakdown (31/31 Passing)
```text
tests/test_bounty_arbiter.py::test_initialization_and_program_status PASSED      [  3%]
tests/test_bounty_arbiter.py::test_initialization_empty_owner_reverts PASSED     [  6%]
tests/test_bounty_arbiter.py::test_initialization_empty_policy_url_reverts PASSED [  9%]
tests/test_bounty_arbiter.py::test_initialization_empty_target_prefix_reverts PASSED [ 12%]
tests/test_bounty_arbiter.py::test_initialization_insecure_policy_url_reverts PASSED [ 16%]
tests/test_bounty_arbiter.py::test_initialization_insecure_target_prefix_reverts PASSED [ 19%]
tests/test_bounty_arbiter.py::test_evidence_url_authority_boundary_validation PASSED [ 22%]
tests/test_bounty_arbiter.py::test_authenticated_submitter_binding PASSED       [ 25%]
tests/test_bounty_arbiter.py::test_submit_report_valid_critical PASSED           [ 29%]
tests/test_bounty_arbiter.py::test_submit_report_valid_tiers PASSED              [ 32%]
tests/test_bounty_arbiter.py::test_submit_report_invalid_creates_no_payout_liability PASSED [ 35%]
tests/test_bounty_arbiter.py::test_fail_closed_policy_fetch_http_error PASSED   [ 38%]
tests/test_bounty_arbiter.py::test_fail_closed_policy_fetch_empty_body PASSED   [ 41%]
tests/test_bounty_arbiter.py::test_fail_closed_evidence_fetch_http_error PASSED [ 45%]
tests/test_bounty_arbiter.py::test_fail_closed_evidence_fetch_empty_body PASSED [ 48%]
tests/test_bounty_arbiter.py::test_fail_closed_missing_mock_or_network_failure PASSED [ 51%]
tests/test_bounty_arbiter.py::test_authoritative_evidence_and_policy_injected_into_prompt PASSED [ 54%]
tests/test_bounty_arbiter.py::test_validator_rejection_validity_disagreement PASSED [ 58%]
tests/test_bounty_arbiter.py::test_validator_rejection_adjacent_severity_mismatch PASSED [ 61%]
tests/test_bounty_arbiter.py::test_validator_rejection_major_severity_divergence PASSED [ 64%]
tests/test_bounty_arbiter.py::test_validator_acceptance_exact_severity_match PASSED [ 67%]
tests/test_bounty_arbiter.py::test_validator_rejection_hallucinated_severity_tier PASSED [ 70%]
tests/test_bounty_arbiter.py::test_validator_rejection_semantic_contradiction PASSED [ 74%]
tests/test_bounty_arbiter.py::test_validator_rejection_malformed_schema PASSED [ 77%]
tests/test_bounty_arbiter.py::test_adjudicated_report_metadata_oracle_primitive PASSED [ 80%]
tests/test_bounty_arbiter.py::test_adjudication_metadata_immutability_and_clean_queries PASSED [ 83%]
tests/test_bounty_arbiter.py::test_adjudication_metadata_invalid_report_zero_units PASSED [ 87%]
tests/test_bounty_arbiter.py::test_get_adjudicated_report_nonexistent_reverts PASSED [ 90%]
tests/test_bounty_arbiter.py::test_submit_report_when_program_inactive_reverts PASSED [ 93%]
tests/test_bounty_arbiter.py::test_submit_report_input_validation PASSED         [ 96%]
tests/test_bounty_arbiter.py::test_administrative_methods_and_access_control PASSED [100%]

============================= 31 passed in 48.89s =============================
```

---

## 6. Deployment & Interaction

### Deploying via GenLayer CLI
```bash
# Start local node
genlayer up

# Deploy BugBountyArbiter with owner, policy URL, and authoritative target prefix
genlayer deploy contracts/bounty_arbiter.py \
  --args '["0x2bd806c97F0e00aF1a1fC3328fA763a9269723C8", "https://raw.githubusercontent.com/JimmyOgb/bug-bounty-arbiter/main/SECURITY.md", "https://raw.githubusercontent.com/JimmyOgb/bug-bounty-arbiter/"]' \
  --network localnet
```

### Deploying via GenLayer Studio
1. Open [GenLayer Studio](https://studio.genlayer.com).
2. Load [`contracts/bounty_arbiter.py`](contracts/bounty_arbiter.py).
3. Specify constructor arguments:
   - `project_owner`: `0x2bd806c97F0e00aF1a1fC3328fA763a9269723C8`
   - `scope_policy_url`: `https://raw.githubusercontent.com/JimmyOgb/bug-bounty-arbiter/main/SECURITY.md`
   - `authoritative_target_prefix`: `https://raw.githubusercontent.com/JimmyOgb/bug-bounty-arbiter/`
4. Click **Deploy**. Use the interactive console to test report triage and query certified adjudication metadata.

---

## 7. Security Policy

Refer to [`SECURITY.md`](SECURITY.md) for full program scope guidelines and component definitions.

---

## 8. License

This project is open-source software licensed under the [MIT License](LICENSE).
