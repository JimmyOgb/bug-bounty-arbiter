# Security Policy & Bug Bounty Scope

This policy outlines the official bug bounty scope, severity rating criteria, and submission rules for programs adjudicated by the **Autonomous Bug Bounty Triage & Severity Arbiter (`BugBountyArbiter`)**.

---

## 1. Program Overview

- **Policy URL**: `https://raw.githubusercontent.com/JimmyOgb/bug-bounty-arbiter/main/SECURITY.md`
- **Triage Mechanism**: Autonomous Multi-Validator GenVM Consensus (`gl.vm.run_nondet_unsafe`)
- **Adjudication Standard**: Automated GenLayer LLM equivalence evaluation against component specifications and this scope policy.

---

## 2. In-Scope Target Components

The following components and vulnerability classes are strictly in-scope for bug bounty submission:

| Component Identifier | Description | In-Scope Vulnerability Classes |
| :--- | :--- | :--- |
| `BugBountyArbiter.py` | Core GenLayer Intelligent Contract | State manipulation, equivalence bypass, unauthorized payout claims, reentrancy, integer overflow / underflow, denial of service. |
| `ConsensusRules` | Multi-validator equivalence checks | Consensus divergence vulnerabilities, validator spoofing, schema-tampering exploits. |
| `VaultCore.sol` / `Treasury` | Associated project custody contracts | Direct theft of funds, unauthorized state minting, flash-loan vulnerabilities, price oracle manipulation. |
| `BridgeRelay` | Cross-chain messaging & validation | Message replay attacks, unauthorized execution, relay censorship. |

---

## 3. Severity Rating Criteria

Submissions are triaged across five standardized tiers aligned with the Immunefi / CVSS 3.1 standard:

### CRITICAL (5,000 Points / Reward Units)
- Direct theft or permanent freezing of user or treasury funds without user interaction.
- Complete state corruption or arbitrary execution of administrative privileges.
- Consensus desynchronization or permanent contract halting.

### HIGH (2,000 Points / Reward Units)
- Theft of unclaimed yield or temporary freezing of user funds requiring complex execution.
- Manipulable oracle pricing vectors with bounded financial impact.
- Griefing attacks with high economic damage to protocol users.

### MEDIUM (500 Points / Reward Units)
- Unbounded loop denial-of-service in non-critical batch processing.
- State inconsistencies that do not lead to direct loss of capital.
- Logic errors leading to incorrect event emissions or metric miscalculations.

### LOW (100 Points / Reward Units)
- Minor edge-case bugs with negligible financial or operational impact.
- Inaccurate parameter validations that fail safely without unintended side-effects.

### NONE (0 Points / Rejected)
- Out-of-scope targets or intended protocol behavior.
- Informational findings, style improvements, or cosmetic issues.
- Third-party dependency issues outside of direct contract integrations.
- Spam, duplicate submissions, or unsubstantiated claims without a clear attack path.

---

## 4. Out-of-Scope Items

The following are strictly out-of-scope and will be adjudicated as `valid: false` with severity `NONE`:
1. Front-end cosmetic glitches, typos, or markdown documentation errors.
2. Attacks requiring physical access to validator hardware or compromises of private keys via social engineering/phishing.
3. Theoretical vulnerabilities without a verifiable Proof-of-Concept (PoC) or exploit path affecting smart contract execution.
4. Volatility-related losses or user mistakes (e.g. sending tokens to wrong addresses).

---

## 5. Submission Guidelines

1. Security researchers must submit their findings directly to the `BugBountyArbiter` contract by invoking `submit_report(researcher, target_component, vulnerability_details)`.
2. Do **not** disclose vulnerabilities publicly prior to formal remediation.
3. Submissions are processed non-deterministically across GenLayer validators; the raw exploit payload is evaluated in ephemeral VM memory and is never permanently written to the ledger, protecting vulnerability details until on-chain resolution.
