# { "Depends": "py-genlayer:1jb45aa8ynh2a9c9xn3b7qqh8sm5q93hwfp7jqmwsfhh8jpz09h6" }

import json
from dataclasses import dataclass
from genlayer import *

ALLOWED_SEVERITIES = {"NONE", "LOW", "MEDIUM", "HIGH", "CRITICAL"}
SEVERITY_RANKS = {"NONE": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}

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


class BugBountyArbiter(gl.Contract):
    """
    Autonomous Bug Bounty Triage & Severity Arbiter (BugBountyArbiter)

    A decentralized smart contract primitive for GenLayer that automates vulnerability
    report intake, AI-driven triage and severity assessment across validators, and on-chain
    payout settlement while preserving strict state hygiene.
    """

    project_owner: str
    scope_policy_url: str
    is_active: bool
    total_submissions: u256
    payout_table: TreeMap[str, u256]
    reports: TreeMap[u256, Report]

    def __init__(self, project_owner: str, scope_policy_url: str):
        if not project_owner or not str(project_owner).strip():
            raise gl.vm.UserError("Project owner identifier cannot be empty")
        if not scope_policy_url or not str(scope_policy_url).strip():
            raise gl.vm.UserError("Scope policy URL cannot be empty")

        self.project_owner = str(project_owner).strip()
        self.scope_policy_url = str(scope_policy_url).strip()
        self.is_active = True
        self.total_submissions = u256(0)

        # Standard bug bounty reward tiers (points / native tokens)
        self.payout_table["NONE"] = u256(0)
        self.payout_table["LOW"] = u256(100)
        self.payout_table["MEDIUM"] = u256(500)
        self.payout_table["HIGH"] = u256(2000)
        self.payout_table["CRITICAL"] = u256(5000)

    def _require_owner(self) -> None:
        sender_str = str(gl.message.sender_address).lower()
        owner_str = self.project_owner.lower()
        if sender_str != owner_str and sender_str.replace("0x", "") != owner_str.replace("0x", ""):
            raise gl.vm.UserError("Only project owner can perform this action")

    @gl.public.write
    def submit_report(
        self,
        researcher: str,
        target_component: str,
        vulnerability_details: str,
    ) -> int:
        """
        Submit a security vulnerability report for multi-validator AI adjudication.

        Runs non-deterministic triage via gl.vm.run_nondet_unsafe with an Equivalence
        Principle validator enforcing validity consensus, schema conformity, and standard
        severity bounds.
        """
        if not self.is_active:
            raise gl.vm.UserError("Bounty program is currently paused or inactive")

        clean_researcher = str(researcher).strip() if researcher else ""
        clean_component = str(target_component).strip() if target_component else ""
        clean_details = str(vulnerability_details).strip() if vulnerability_details else ""

        if not clean_researcher:
            raise gl.vm.UserError("Researcher identity/address cannot be empty")
        if not clean_component:
            raise gl.vm.UserError("Target component cannot be empty")
        if not clean_details:
            raise gl.vm.UserError("Vulnerability details cannot be empty")

        policy_url = self.scope_policy_url

        def leader_fn() -> dict:
            prompt = f"""You are an autonomous smart contract security auditor and bug bounty arbiter.
Evaluate the following vulnerability report submitted against the specified target component.

Scope Policy URL: {policy_url}
Target Component: {clean_component}
Submission Details:
\"\"\"{clean_details}\"\"\"

Evaluation Guidelines:
1. Assess whether the submission describes a genuine, in-scope security vulnerability affecting '{clean_component}'.
2. "valid": Set to true if the report details a real security flaw. Set to false if it is spam, invalid, informational only, out-of-scope, or intended behavior.
3. "severity": Standard classification tier strictly chosen from: "NONE", "LOW", "MEDIUM", "HIGH", "CRITICAL".
   - If "valid" is false, "severity" MUST strictly be "NONE".
   - If "valid" is true, assign "LOW", "MEDIUM", "HIGH", or "CRITICAL" reflecting practical exploitability and financial/governance impact.
4. "rationale": Provide a concise technical explanation (under 250 characters).

Return strictly a JSON object conforming to:
{{
  "valid": true,
  "severity": "CRITICAL",
  "rationale": "High impact exploitability reasoning"
}}"""
            raw_res = gl.nondet.exec_prompt(prompt, response_format="json")
            if isinstance(raw_res, str):
                raw_res = json.loads(raw_res)
            if not isinstance(raw_res, dict):
                raise gl.vm.UserError("LLM output is not a JSON dictionary")

            raw_valid = raw_res.get("valid")
            if isinstance(raw_valid, str):
                valid_val = raw_valid.strip().lower() in ("true", "1", "yes")
            else:
                valid_val = bool(raw_valid)

            raw_sev = str(raw_res.get("severity", "NONE")).strip().upper()
            if raw_sev not in ALLOWED_SEVERITIES:
                raise gl.vm.UserError(f"Invalid severity tier: {raw_sev}")

            if not valid_val:
                raw_sev = "NONE"
            elif raw_sev == "NONE":
                valid_val = False

            rationale = str(raw_res.get("rationale", "")).strip()[:280]
            if not rationale:
                rationale = "Triage completed based on vulnerability specification."

            return {
                "valid": valid_val,
                "severity": raw_sev,
                "rationale": rationale,
            }

        def validator_fn(leaders_res: gl.vm.Result) -> bool:
            # 1. Ensure leader returned normally
            if not isinstance(leaders_res, gl.vm.Return):
                return False

            leader_payload = leaders_res.calldata
            if not isinstance(leader_payload, dict):
                return False

            # 2. Check required schema fields
            for key in ("valid", "severity", "rationale"):
                if key not in leader_payload:
                    return False

            leader_valid = leader_payload["valid"]
            leader_sev = str(leader_payload["severity"]).strip().upper()
            leader_rationale = str(leader_payload["rationale"]).strip()

            if not isinstance(leader_valid, bool):
                return False
            if not leader_rationale:
                return False

            # 3. Reject transactions where the leader hallucinates invalid tiers
            if leader_sev not in ALLOWED_SEVERITIES:
                return False

            # 4. Reject semantic contradictions in leader's proposal
            if not leader_valid and leader_sev != "NONE":
                return False
            if leader_valid and leader_sev == "NONE":
                return False

            # 5. Validator independently runs evaluation
            try:
                val_payload = leader_fn()
            except Exception:
                return False

            if not isinstance(val_payload, dict):
                return False

            val_valid = val_payload.get("valid")
            val_sev = str(val_payload.get("severity", "")).strip().upper()

            # 6. Equivalence Principle: Strict equality on 'valid' boolean
            if leader_valid != val_valid:
                return False

            # 7. Ensure validator severity matches standard tiers
            if val_sev not in ALLOWED_SEVERITIES:
                return False

            # 8. If invalid, both must agree on NONE severity
            if not leader_valid:
                return leader_sev == "NONE" and val_sev == "NONE"

            # 9. When valid, neither can be NONE
            if leader_sev == "NONE" or val_sev == "NONE":
                return False

            # 10. Severity tier agreement: allow adjacent tier tolerance (diff <= 1)
            # Rejects major divergences where leader and validator assess risk differently
            leader_rank = SEVERITY_RANKS.get(leader_sev, -1)
            val_rank = SEVERITY_RANKS.get(val_sev, -1)
            if leader_rank < 1 or val_rank < 1:
                return False

            if abs(leader_rank - val_rank) > 1:
                return False

            return True

        adjudication = gl.vm.run_nondet_unsafe(leader_fn, validator_fn)

        is_valid = bool(adjudication["valid"])
        severity = str(adjudication["severity"]).strip().upper()
        rationale = str(adjudication["rationale"]).strip()

        if is_valid and severity in ALLOWED_SEVERITIES:
            payout_due = self.payout_table[severity]
        else:
            severity = "NONE"
            payout_due = u256(0)

        new_report_id = int(self.total_submissions) + 1
        self.total_submissions = u256(new_report_id)

        # State hygiene: store only sanitized metadata, never raw exploit payloads
        self.reports[u256(new_report_id)] = Report(
            id=u256(new_report_id),
            researcher=clean_researcher,
            target_component=clean_component,
            valid=is_valid,
            severity=severity,
            rationale=rationale,
            payout_due=payout_due,
            claimed=False,
        )

        return new_report_id

    @gl.public.write
    def claim_payout(self, report_id: int) -> int:
        """
        Claim the bounty payout for an adjudicated valid report.
        Strict gating prevents double claims or claiming on invalid/zero-payout reports.
        """
        if report_id <= 0 or report_id > int(self.total_submissions):
            raise gl.vm.UserError("Report does not exist")

        report = self.reports[u256(report_id)]

        if not report.valid:
            raise gl.vm.UserError("Cannot claim payout on invalid or rejected report")

        if report.claimed:
            raise gl.vm.UserError("Payout has already been claimed for this report")

        payout = int(report.payout_due)
        if payout <= 0:
            raise gl.vm.UserError("No payout due for this report")

        report.claimed = True
        self.reports[u256(report_id)] = report
        return payout

    @gl.public.view
    def get_report(self, report_id: int) -> dict:
        """
        View sanitized on-chain metadata for a submitted report.
        """
        if report_id <= 0 or report_id > int(self.total_submissions):
            raise gl.vm.UserError("Report does not exist")

        r = self.reports[u256(report_id)]
        return {
            "id": int(r.id),
            "researcher": str(r.researcher),
            "target_component": str(r.target_component),
            "valid": bool(r.valid),
            "severity": str(r.severity),
            "rationale": str(r.rationale),
            "payout_due": int(r.payout_due),
            "claimed": bool(r.claimed),
        }

    @gl.public.view
    def get_program_status(self) -> dict:
        """
        View bounty program status, configuration, and current payout table.
        """
        return {
            "project_owner": str(self.project_owner),
            "scope_policy_url": str(self.scope_policy_url),
            "is_active": bool(self.is_active),
            "total_submissions": int(self.total_submissions),
            "payout_table": {
                "NONE": int(self.payout_table["NONE"]),
                "LOW": int(self.payout_table["LOW"]),
                "MEDIUM": int(self.payout_table["MEDIUM"]),
                "HIGH": int(self.payout_table["HIGH"]),
                "CRITICAL": int(self.payout_table["CRITICAL"]),
            },
        }

    @gl.public.write
    def set_active(self, is_active: bool) -> None:
        """Administrative method to pause or unpause the bounty program."""
        self._require_owner()
        self.is_active = is_active

    @gl.public.write
    def update_payout(self, severity: str, amount: int) -> None:
        """Administrative method to update payout table values."""
        self._require_owner()
        sev = str(severity).strip().upper()
        if sev not in ALLOWED_SEVERITIES:
            raise gl.vm.UserError(f"Invalid severity tier: {severity}")
        if amount < 0:
            raise gl.vm.UserError("Payout amount cannot be negative")
        self.payout_table[sev] = u256(amount)

    @gl.public.write
    def update_scope_policy(self, new_scope_url: str) -> None:
        """Administrative method to update the scope policy URL."""
        self._require_owner()
        clean_url = str(new_scope_url).strip() if new_scope_url else ""
        if not clean_url:
            raise gl.vm.UserError("Scope policy URL cannot be empty")
        self.scope_policy_url = clean_url
