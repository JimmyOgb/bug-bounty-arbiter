# { "Depends": "py-genlayer:1jb45aa8ynh2a9c9xn3b7qqh8sm5q93hwfp7jqmwsfhh8jpz09h6" }

import json
import urllib.parse
from dataclasses import dataclass
from genlayer import *

ALLOWED_SEVERITIES = {"NONE", "LOW", "MEDIUM", "HIGH", "CRITICAL"}
SEVERITY_RANKS = {"NONE": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}


def validate_secure_url(url: str, param_name: str = "URL") -> urllib.parse.SplitResult:
    """
    Deconstructs and validates URL scheme, host/authority, path, query, and credentials.
    Enforces scheme == 'https', non-empty host, rejects query strings, fragments, userinfo,
    and path traversal elements ('..').
    """
    if not url or not isinstance(url, str) or not url.strip():
        raise gl.vm.UserError(f"{param_name} cannot be empty")

    clean_url = url.strip()
    try:
        parsed = urllib.parse.urlsplit(clean_url)
    except Exception as exc:
        raise gl.vm.UserError(f"{param_name} violates authoritative domain boundary: malformed URL ({exc})")

    if parsed.scheme.lower() != "https":
        raise gl.vm.UserError(f"{param_name} violates authoritative domain boundary: scheme must be https")

    if not parsed.netloc or not parsed.hostname:
        raise gl.vm.UserError(f"{param_name} violates authoritative domain boundary: missing host")

    if "@" in parsed.netloc or parsed.username is not None or parsed.password is not None:
        raise gl.vm.UserError(
            f"{param_name} violates authoritative domain boundary: credentials or userinfo not permitted"
        )

    if parsed.query:
        raise gl.vm.UserError(f"{param_name} violates authoritative domain boundary: query strings not permitted")

    if parsed.fragment:
        raise gl.vm.UserError(f"{param_name} violates authoritative domain boundary: fragments not permitted")

    unquoted_path = urllib.parse.unquote(parsed.path)
    segments = unquoted_path.split("/")
    if any(seg == ".." for seg in segments):
        raise gl.vm.UserError(
            f"{param_name} violates authoritative domain boundary: path traversal elements not permitted"
        )

    return parsed


def validate_url_against_boundary(url: str, prefix: str) -> None:
    """
    Enforces parsed origin and path-boundary validation:
    1. Scheme must be https for both prefix and target URL.
    2. Exact host match against authoritative domain (case-insensitive).
    3. Exact port match if specified.
    4. Path prefix boundary checking such that path segments strictly start with the allowed path root,
       preventing lookalike names (e.g. bug-bounty-arbiter-fake).
    """
    prefix_parsed = validate_secure_url(prefix, "Authoritative target prefix")
    url_parsed = validate_secure_url(url, "Evidence URL")

    # Enforce exact host match against authoritative domain
    if url_parsed.hostname.lower() != prefix_parsed.hostname.lower():
        raise gl.vm.UserError("Evidence URL violates authoritative domain boundary: hostname mismatch")

    # Enforce exact port match if defined
    if url_parsed.port != prefix_parsed.port:
        raise gl.vm.UserError("Evidence URL violates authoritative domain boundary: port mismatch")

    # Enforce strict path prefix boundary by path segments
    prefix_segments = [s for s in prefix_parsed.path.split("/") if s]
    url_segments = [s for s in url_parsed.path.split("/") if s]

    if len(url_segments) < len(prefix_segments):
        raise gl.vm.UserError("Evidence URL violates authoritative domain boundary: path too short")

    for p_seg, u_seg in zip(prefix_segments, url_segments):
        if p_seg != u_seg:
            raise gl.vm.UserError("Evidence URL violates authoritative domain boundary: path prefix mismatch")


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


Report = ReportMetadata


class BugBountyArbiter(gl.Contract):
    """
    Autonomous Bug Bounty Triage & Severity Arbiter (BugBountyArbiter)

    A decentralized smart contract adjudication arbiter and oracle primitive for GenLayer.
    Automates vulnerability report intake, authenticated submitter binding (msg.sender),
    live policy-grounded and target-evidence-grounded multi-validator AI triage, fail-closed
    consensus, exact severity consensus, and certified on-chain adjudication metadata generation
    for downstream consumption by vaults, escrows, and DAOs while preserving strict state hygiene
    and parsed origin/path-boundary validation.
    """

    project_owner: str
    scope_policy_url: str
    authoritative_target_prefix: str
    is_active: bool
    total_submissions: u256
    payout_table: TreeMap[str, u256]
    reports: TreeMap[u256, ReportMetadata]

    def __init__(
        self,
        project_owner: str,
        scope_policy_url: str,
        authoritative_target_prefix: str,
    ):
        if not project_owner or not str(project_owner).strip():
            raise gl.vm.UserError("Project owner identifier cannot be empty")
        if not scope_policy_url or not str(scope_policy_url).strip():
            raise gl.vm.UserError("Scope policy URL cannot be empty")
        if not authoritative_target_prefix or not str(authoritative_target_prefix).strip():
            raise gl.vm.UserError("Authoritative target prefix cannot be empty")

        clean_policy_url = str(scope_policy_url).strip()
        clean_target_prefix = str(authoritative_target_prefix).strip()

        # Robust URL validation on scope policy and target prefix
        validate_secure_url(clean_policy_url, "Scope policy URL")
        validate_secure_url(clean_target_prefix, "Authoritative target prefix")

        self.project_owner = str(project_owner).strip()
        self.scope_policy_url = clean_policy_url
        self.authoritative_target_prefix = clean_target_prefix
        self.is_active = True
        self.total_submissions = u256(0)

        # Standard bug bounty recommendation tiers (adjudication metadata points / units)
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
        target_evidence_url: str,
        vulnerability_details: str,
    ) -> int:
        """
        Submit a security vulnerability report for multi-validator AI adjudication.
        Binds the report directly to the authenticated transaction caller (gl.message.sender).

        Runs non-deterministic triage via gl.vm.run_nondet:
        1. Enforces parsed origin and path-boundary validation on target_evidence_url.
        2. Strict fail-closed live acquisition of both scope policy and target evidence.
        3. Multi-validator comparative Equivalence Principle enforcing exact agreement on
           validity boolean and exact severity tier to deterministically bind recommended_payout_units.
        """
        if not self.is_active:
            raise gl.vm.UserError("Bounty program is currently paused or inactive")

        # Automatically bind report to authenticated transaction caller
        try:
            caller: Address = gl.message.sender  # type: ignore
        except AttributeError:
            caller = gl.message.sender_address

        clean_evidence_url = str(target_evidence_url).strip() if target_evidence_url else ""
        clean_details = str(vulnerability_details).strip() if vulnerability_details else ""

        if not clean_evidence_url:
            raise gl.vm.UserError("Target evidence URL cannot be empty")
        if not clean_details:
            raise gl.vm.UserError("Vulnerability details cannot be empty")

        # Enforce robust parsed origin and path-boundary validation
        validate_url_against_boundary(clean_evidence_url, self.authoritative_target_prefix)

        policy_url = self.scope_policy_url
        prefix = self.authoritative_target_prefix

        def leader_fn() -> dict:
            # 1. Fetch scope policy with fail-closed checks
            try:
                policy_res = gl.nondet.web.get(policy_url)
            except Exception:
                raise gl.vm.UserError(
                    "Failed to acquire authoritative scope policy or target evidence; failing closed."
                )

            if policy_res.status != 200:
                raise gl.vm.UserError(
                    "Failed to acquire authoritative scope policy or target evidence; failing closed."
                )

            policy_bytes = policy_res.body or b""
            policy_text = policy_bytes.decode("utf-8", errors="replace").strip()
            if not policy_text:
                raise gl.vm.UserError(
                    "Failed to acquire authoritative scope policy or target evidence; failing closed."
                )

            # 2. Fetch target evidence with fail-closed checks
            try:
                evidence_res = gl.nondet.web.get(clean_evidence_url)
            except Exception:
                raise gl.vm.UserError(
                    "Failed to acquire authoritative scope policy or target evidence; failing closed."
                )

            if evidence_res.status != 200:
                raise gl.vm.UserError(
                    "Failed to acquire authoritative scope policy or target evidence; failing closed."
                )

            evidence_bytes = evidence_res.body or b""
            evidence_text = evidence_bytes.decode("utf-8", errors="replace").strip()
            if not evidence_text:
                raise gl.vm.UserError(
                    "Failed to acquire authoritative scope policy or target evidence; failing closed."
                )

            # 3. Safe truncation for prompt context
            policy_snippet = policy_text[:4000]
            evidence_snippet = evidence_text[:4000]

            prompt = f"""You are an autonomous smart contract security auditor and bug bounty arbiter.
Evaluate the following vulnerability report submitted with authoritative target evidence against the project's scope policy.

=== AUTHORITATIVE SCOPE POLICY ({policy_url}) ===
{policy_snippet}

=== AUTHORITATIVE TARGET EVIDENCE / REPRODUCIBLE PROOF ({clean_evidence_url}) ===
{evidence_snippet}

=== RESEARCHER SUBMISSION DETAILS ===
Researcher Address: {caller}
Target Evidence URL: {clean_evidence_url}
Vulnerability Details & Steps to Reproduce:
\"\"\"{clean_details}\"\"\"

Evaluation Guidelines:
1. Objectively verify whether the fetched target evidence/code demonstrates the claimed exploit or vulnerability against the authoritative scope policy.
2. If the claimed vulnerability is refuted by the authoritative evidence, out of scope, intended functionality, or non-reproducible, mark it invalid.
3. "valid": Set to true ONLY IF the fetched target evidence objectively demonstrates a genuine, in-scope security vulnerability. Set to false otherwise.
4. "severity": Standard classification tier strictly chosen from: "NONE", "LOW", "MEDIUM", "HIGH", "CRITICAL".
   - If "valid" is false, "severity" MUST strictly be "NONE".
   - If "valid" is true, assign "LOW", "MEDIUM", "HIGH", or "CRITICAL" reflecting practical exploitability, financial/governance impact, and scope policy definitions.
5. "rationale": Provide a concise technical explanation (under 250 characters).

Return strictly a JSON object conforming to:
{{
  "valid": true,
  "severity": "CRITICAL",
  "rationale": "High impact exploitability verified with authoritative evidence."
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
                rationale = "Triage completed based on authoritative evidence."

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

            # 3. Reject transactions where the leader proposes invalid tiers
            if leader_sev not in ALLOWED_SEVERITIES:
                return False

            # 4. Reject semantic contradictions in leader's proposal
            if not leader_valid and leader_sev != "NONE":
                return False
            if leader_valid and leader_sev == "NONE":
                return False

            # 5. Independent Authority Validation:
            # Validators independently verify that the target evidence URL obeys the authoritative origin and path boundary
            try:
                validate_url_against_boundary(clean_evidence_url, prefix)
            except Exception:
                return False

            # 6. Validator independently runs leader_fn()
            # This independently fetches both URLs (failing closed if unavailable/empty/non-200)
            # and runs the LLM evaluation.
            try:
                val_payload = leader_fn()
            except Exception:
                return False

            if not isinstance(val_payload, dict):
                return False

            val_valid = val_payload.get("valid")
            val_sev = str(val_payload.get("severity", "")).strip().upper()

            # 7. Equivalence Principle: Strict equality on 'valid' boolean
            if leader_valid != val_valid:
                return False

            # 8. Ensure validator severity matches standard tiers
            if val_sev not in ALLOWED_SEVERITIES:
                return False

            # 9. Strict Severity Equivalence (Exact Binding):
            # Validators MUST independently agree on the EXACT severity tier.
            # Zero tolerance for adjacent tier drift or divergence.
            if leader_sev != val_sev:
                return False

            return True

        adjudication = gl.vm.run_nondet(leader_fn, validator_fn)

        is_valid = bool(adjudication["valid"])
        severity = str(adjudication["severity"]).strip().upper()
        rationale = str(adjudication["rationale"]).strip()

        if is_valid and severity in ALLOWED_SEVERITIES:
            recommended_payout_units = self.payout_table[severity]
        else:
            severity = "NONE"
            recommended_payout_units = u256(0)

        new_report_id = int(self.total_submissions) + 1
        self.total_submissions = u256(new_report_id)

        # State hygiene: store only sanitized metadata, never raw exploit payloads
        self.reports[u256(new_report_id)] = ReportMetadata(
            id=u256(new_report_id),
            researcher=caller,
            target_evidence_url=clean_evidence_url,
            valid=is_valid,
            severity=severity,
            rationale=rationale,
            recommended_payout_units=recommended_payout_units,
        )

        return new_report_id

    @gl.public.view
    def get_adjudicated_report(self, report_id: u256) -> ReportMetadata:
        """
        View certified adjudication metadata for downstream consumption (vaults, escrows, DAOs).
        """
        if int(report_id) <= 0 or int(report_id) > int(self.total_submissions):
            raise gl.vm.UserError("Report does not exist")

        return self.reports[u256(int(report_id))]

    @gl.public.view
    def get_report(self, report_id: u256) -> dict:
        """
        View serialized on-chain adjudication metadata for a submitted report.
        """
        if int(report_id) <= 0 or int(report_id) > int(self.total_submissions):
            raise gl.vm.UserError("Report does not exist")

        r = self.reports[u256(int(report_id))]
        return {
            "id": int(r.id),
            "researcher": str(r.researcher),
            "target_evidence_url": str(r.target_evidence_url),
            "valid": bool(r.valid),
            "severity": str(r.severity),
            "rationale": str(r.rationale),
            "recommended_payout_units": int(r.recommended_payout_units),
            "payout_due": int(r.recommended_payout_units),
        }

    @gl.public.view
    def get_program_status(self) -> dict:
        """
        View bounty program status, configuration, and current recommendation table.
        """
        return {
            "project_owner": str(self.project_owner),
            "scope_policy_url": str(self.scope_policy_url),
            "authoritative_target_prefix": str(self.authoritative_target_prefix),
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
        """Administrative method to update payout recommendation table values."""
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
        validate_secure_url(clean_url, "Scope policy URL")
        self.scope_policy_url = clean_url

    @gl.public.write
    def update_authoritative_target_prefix(self, new_prefix: str) -> None:
        """Administrative method to update the authoritative target prefix."""
        self._require_owner()
        clean_prefix = str(new_prefix).strip() if new_prefix else ""
        if not clean_prefix:
            raise gl.vm.UserError("Authoritative target prefix cannot be empty")
        validate_secure_url(clean_prefix, "Authoritative target prefix")
        self.authoritative_target_prefix = clean_prefix
