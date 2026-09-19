import json
import pytest

DEFAULT_POLICY_URL = "https://security.example.io/policy.md"
DEFAULT_TARGET_PREFIX = "https://raw.githubusercontent.com/JimmyOgb/bug-bounty-arbiter/"
DEFAULT_EVIDENCE_URL = "https://raw.githubusercontent.com/JimmyOgb/bug-bounty-arbiter/main/contracts/VaultCore.sol"

DEFAULT_POLICY_BODY = """# Bug Bounty Program Scope Policy
## Authorized In-Scope Components:
- VaultCore.sol: Core asset vault and liquidity pool contracts.
- DexRouter.sol: Automated market maker router.
- Bridge.sol: Cross-chain messaging relay endpoint.
- Staking.sol: Reward staking and distribution.
- Oracle.sol: Median price feed integration.
- Token.sol: ERC-20 token implementation.

## Out-of-Scope:
- GovernanceToken.sol: Informational only, public features.
- Denial of service attacks requiring extreme resources.
"""

DEFAULT_EVIDENCE_BODY = """// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract VaultCore {
    mapping(address => uint256) public balances;

    function withdrawAll() external {
        uint256 amount = balances[msg.sender];
        require(amount > 0, "No balance");
        (bool ok, ) = msg.sender.call{value: amount}("");
        require(ok, "Transfer failed");
        balances[msg.sender] = 0; // State updated after external call
    }
}
"""


@pytest.fixture(autouse=True)
def default_web_mock(direct_vm):
    """Automatically mock scope policy and authoritative evidence web fetches for all test cases."""
    direct_vm.mock_web(
        r".*security\.example\.io.*",
        {"status": 200, "body": DEFAULT_POLICY_BODY},
    )
    direct_vm.mock_web(
        r".*raw\.githubusercontent\.com/JimmyOgb/.*",
        {"status": 200, "body": DEFAULT_EVIDENCE_BODY},
    )


def mock_policy(
    direct_vm,
    url_pattern: str = r".*security\.example\.io.*",
    body: str = DEFAULT_POLICY_BODY,
    status: int = 200,
):
    """Helper to re-register scope policy web mock after clear_mocks()."""
    direct_vm.mock_web(url_pattern, {"status": status, "body": body})


def mock_evidence(
    direct_vm,
    url_pattern: str = r".*raw\.githubusercontent\.com/JimmyOgb/.*",
    body: str = DEFAULT_EVIDENCE_BODY,
    status: int = 200,
):
    """Helper to re-register target evidence web mock after clear_mocks()."""
    direct_vm.mock_web(url_pattern, {"status": status, "body": body})


def test_initialization_and_program_status(direct_vm, direct_deploy, direct_alice):
    owner = "0x" + direct_alice.hex()
    policy_url = DEFAULT_POLICY_URL
    prefix = DEFAULT_TARGET_PREFIX

    contract = direct_deploy("contracts/bounty_arbiter.py", owner, policy_url, prefix)
    status = contract.get_program_status()

    assert status["project_owner"] == owner
    assert status["scope_policy_url"] == policy_url
    assert status["authoritative_target_prefix"] == prefix
    assert status["is_active"] is True
    assert status["total_submissions"] == 0

    payouts = status["payout_table"]
    assert payouts["NONE"] == 0
    assert payouts["LOW"] == 100
    assert payouts["MEDIUM"] == 500
    assert payouts["HIGH"] == 2000
    assert payouts["CRITICAL"] == 5000


def test_initialization_empty_owner_reverts(direct_vm, direct_deploy):
    with direct_vm.expect_revert("Project owner identifier cannot be empty"):
        direct_deploy("contracts/bounty_arbiter.py", "", DEFAULT_POLICY_URL, DEFAULT_TARGET_PREFIX)


def test_initialization_empty_policy_url_reverts(direct_vm, direct_deploy):
    with direct_vm.expect_revert("Scope policy URL cannot be empty"):
        direct_deploy("contracts/bounty_arbiter.py", "0xOwner", "", DEFAULT_TARGET_PREFIX)


def test_initialization_empty_target_prefix_reverts(direct_vm, direct_deploy):
    with direct_vm.expect_revert("Authoritative target prefix cannot be empty"):
        direct_deploy("contracts/bounty_arbiter.py", "0xOwner", DEFAULT_POLICY_URL, "")


def test_evidence_url_authority_boundary_validation(direct_vm, direct_deploy, direct_alice):
    """
    Enforce Authority: Verify that target_evidence_url must start with authoritative_target_prefix.
    Non-matching URLs revert immediately with 'Evidence URL violates authoritative domain boundary'
    and create zero report state.
    """
    contract = direct_deploy(
        "contracts/bounty_arbiter.py",
        "0x" + direct_alice.hex(),
        DEFAULT_POLICY_URL,
        DEFAULT_TARGET_PREFIX,
    )
    direct_vm.sender = direct_alice

    unauthorized_urls = [
        "https://attacker.evil.com/fake_proof.sol",
        "https://raw.githubusercontent.com/MaliciousActor/exploit/main.sol",
        "https://pastebin.com/raw/exploit",
    ]

    for unauth_url in unauthorized_urls:
        with direct_vm.expect_revert("Evidence URL violates authoritative domain boundary"):
            contract.submit_report(
                "0xResearcher",
                unauth_url,
                "Exploit details pointing outside authoritative boundary",
            )

    status = contract.get_program_status()
    assert status["total_submissions"] == 0


def test_submit_report_valid_critical(direct_vm, direct_deploy, direct_alice):
    contract = direct_deploy(
        "contracts/bounty_arbiter.py",
        "0x" + direct_alice.hex(),
        DEFAULT_POLICY_URL,
        DEFAULT_TARGET_PREFIX,
    )
    direct_vm.sender = direct_alice

    llm_payload = {
        "valid": True,
        "severity": "CRITICAL",
        "rationale": "Reentrancy in withdrawAll() allows full pool drain.",
    }
    direct_vm.mock_llm(r".*", json.dumps(llm_payload))

    report_id = contract.submit_report(
        "0xResearcher1",
        DEFAULT_EVIDENCE_URL,
        "Reentrancy vector identified via cross-function state update desync in VaultCore.",
    )
    assert report_id == 1

    # Multi-validator consensus verification
    val_passed = direct_vm.run_validator()
    assert val_passed is True

    # Check on-chain stored metadata
    report = contract.get_report(1)
    assert report["id"] == 1
    assert report["researcher"] == "0xResearcher1"
    assert report["target_evidence_url"] == DEFAULT_EVIDENCE_URL
    assert report["valid"] is True
    assert report["severity"] == "CRITICAL"
    assert report["rationale"] == "Reentrancy in withdrawAll() allows full pool drain."
    assert report["payout_due"] == 5000
    assert report["claimed"] is False

    # Check program status reflects submission count
    status = contract.get_program_status()
    assert status["total_submissions"] == 1


def test_submit_report_valid_tiers(direct_vm, direct_deploy, direct_alice):
    contract = direct_deploy(
        "contracts/bounty_arbiter.py",
        "0x" + direct_alice.hex(),
        DEFAULT_POLICY_URL,
        DEFAULT_TARGET_PREFIX,
    )
    direct_vm.sender = direct_alice

    tiers = [
        ("HIGH", 2000, "Oracle latency manipulation"),
        ("MEDIUM", 500, "Unbounded loop denial-of-service in batchTransfer"),
        ("LOW", 100, "Inaccurate event emission on fee update"),
    ]

    for idx, (tier, expected_payout, rationale) in enumerate(tiers, start=1):
        direct_vm.clear_mocks()
        mock_policy(direct_vm)
        mock_evidence(direct_vm)
        direct_vm.mock_llm(
            r".*",
            json.dumps({"valid": True, "severity": tier, "rationale": rationale}),
        )

        rep_id = contract.submit_report(
            f"0xResearcher_{tier}",
            DEFAULT_EVIDENCE_URL,
            f"Technical report details for {tier}",
        )
        assert rep_id == idx

        val_ok = direct_vm.run_validator()
        assert val_ok is True

        rep = contract.get_report(rep_id)
        assert rep["valid"] is True
        assert rep["severity"] == tier
        assert rep["payout_due"] == expected_payout
        assert rep["claimed"] is False


def test_submit_report_invalid_creates_no_payout_liability(direct_vm, direct_deploy, direct_alice):
    """
    Submitting an invalid report or spam results in valid=False, severity=NONE, payout_due=0.
    No payout liability can be claimed.
    """
    contract = direct_deploy(
        "contracts/bounty_arbiter.py",
        "0x" + direct_alice.hex(),
        DEFAULT_POLICY_URL,
        DEFAULT_TARGET_PREFIX,
    )
    direct_vm.sender = direct_alice

    direct_vm.mock_llm(
        r".*",
        json.dumps({
            "valid": False,
            "severity": "NONE",
            "rationale": "Report describes intended public feature, not a vulnerability.",
        }),
    )

    report_id = contract.submit_report(
        "0xSpammer",
        DEFAULT_EVIDENCE_URL,
        "Token can be transferred to any address.",
    )
    assert report_id == 1

    val_passed = direct_vm.run_validator()
    assert val_passed is True

    report = contract.get_report(1)
    assert report["valid"] is False
    assert report["severity"] == "NONE"
    assert report["payout_due"] == 0
    assert report["claimed"] is False

    # Ensure no payout can ever be claimed
    with direct_vm.expect_revert("Cannot claim payout on invalid or rejected report"):
        contract.claim_payout(1)


def test_fail_closed_policy_fetch_http_error(direct_vm, direct_deploy, direct_alice):
    """
    Fail-Closed Gate: If scope policy fetch returns non-200 (404/500), execution immediately reverts
    before any report state or payout liability is recorded.
    """
    contract = direct_deploy(
        "contracts/bounty_arbiter.py",
        "0x" + direct_alice.hex(),
        DEFAULT_POLICY_URL,
        DEFAULT_TARGET_PREFIX,
    )
    direct_vm.sender = direct_alice

    # Mock HTTP 404 failure on policy
    direct_vm.clear_mocks()
    mock_policy(direct_vm, status=404, body="Policy Not Found")
    mock_evidence(direct_vm, status=200, body=DEFAULT_EVIDENCE_BODY)

    with direct_vm.expect_revert("Failed to acquire authoritative scope policy or target evidence; failing closed."):
        contract.submit_report("0xResearcher", DEFAULT_EVIDENCE_URL, "Bug details")

    # Mock HTTP 500 failure on policy
    direct_vm.clear_mocks()
    mock_policy(direct_vm, status=500, body="Internal Server Error")
    mock_evidence(direct_vm, status=200, body=DEFAULT_EVIDENCE_BODY)

    with direct_vm.expect_revert("Failed to acquire authoritative scope policy or target evidence; failing closed."):
        contract.submit_report("0xResearcher", DEFAULT_EVIDENCE_URL, "Bug details")

    status = contract.get_program_status()
    assert status["total_submissions"] == 0


def test_fail_closed_policy_fetch_empty_body(direct_vm, direct_deploy, direct_alice):
    """
    Fail-Closed Gate: Empty scope policy body causes safe contract revert before adjudication.
    """
    contract = direct_deploy(
        "contracts/bounty_arbiter.py",
        "0x" + direct_alice.hex(),
        DEFAULT_POLICY_URL,
        DEFAULT_TARGET_PREFIX,
    )
    direct_vm.sender = direct_alice

    direct_vm.clear_mocks()
    mock_policy(direct_vm, status=200, body="   ")
    mock_evidence(direct_vm, status=200, body=DEFAULT_EVIDENCE_BODY)

    with direct_vm.expect_revert("Failed to acquire authoritative scope policy or target evidence; failing closed."):
        contract.submit_report("0xResearcher", DEFAULT_EVIDENCE_URL, "Bug details")

    assert contract.get_program_status()["total_submissions"] == 0


def test_fail_closed_evidence_fetch_http_error(direct_vm, direct_deploy, direct_alice):
    """
    Fail-Closed Gate: If target evidence fetch returns non-200 (404/500), execution immediately reverts
    before any report state or payout liability is recorded.
    """
    contract = direct_deploy(
        "contracts/bounty_arbiter.py",
        "0x" + direct_alice.hex(),
        DEFAULT_POLICY_URL,
        DEFAULT_TARGET_PREFIX,
    )
    direct_vm.sender = direct_alice

    # Mock HTTP 404 failure on evidence
    direct_vm.clear_mocks()
    mock_policy(direct_vm, status=200, body=DEFAULT_POLICY_BODY)
    mock_evidence(direct_vm, status=404, body="Evidence Not Found")

    with direct_vm.expect_revert("Failed to acquire authoritative scope policy or target evidence; failing closed."):
        contract.submit_report("0xResearcher", DEFAULT_EVIDENCE_URL, "Bug details")

    # Mock HTTP 500 failure on evidence
    direct_vm.clear_mocks()
    mock_policy(direct_vm, status=200, body=DEFAULT_POLICY_BODY)
    mock_evidence(direct_vm, status=500, body="Internal Server Error")

    with direct_vm.expect_revert("Failed to acquire authoritative scope policy or target evidence; failing closed."):
        contract.submit_report("0xResearcher", DEFAULT_EVIDENCE_URL, "Bug details")

    assert contract.get_program_status()["total_submissions"] == 0


def test_fail_closed_evidence_fetch_empty_body(direct_vm, direct_deploy, direct_alice):
    """
    Fail-Closed Gate: Empty target evidence payload causes safe contract revert before adjudication.
    """
    contract = direct_deploy(
        "contracts/bounty_arbiter.py",
        "0x" + direct_alice.hex(),
        DEFAULT_POLICY_URL,
        DEFAULT_TARGET_PREFIX,
    )
    direct_vm.sender = direct_alice

    direct_vm.clear_mocks()
    mock_policy(direct_vm, status=200, body=DEFAULT_POLICY_BODY)
    mock_evidence(direct_vm, status=200, body="")

    with direct_vm.expect_revert("Failed to acquire authoritative scope policy or target evidence; failing closed."):
        contract.submit_report("0xResearcher", DEFAULT_EVIDENCE_URL, "Bug details")

    assert contract.get_program_status()["total_submissions"] == 0


def test_fail_closed_missing_mock_or_network_failure(direct_vm, direct_deploy, direct_alice):
    """
    If web requests fail or are unmocked/unreachable, fail-closed reverts safely.
    """
    contract = direct_deploy(
        "contracts/bounty_arbiter.py",
        "0x" + direct_alice.hex(),
        DEFAULT_POLICY_URL,
        DEFAULT_TARGET_PREFIX,
    )
    direct_vm.sender = direct_alice

    direct_vm.clear_mocks()
    with direct_vm.expect_revert("Failed to acquire authoritative scope policy or target evidence; failing closed."):
        contract.submit_report("0xResearcher", DEFAULT_EVIDENCE_URL, "Bug details")

    assert contract.get_program_status()["total_submissions"] == 0


def test_authoritative_evidence_and_policy_injected_into_prompt(direct_vm, direct_deploy, direct_alice):
    """
    Verify that BOTH authoritative scope policy AND authoritative target evidence/code
    are fetched and injected into the LLM evaluation prompt.
    """
    custom_policy_url = "https://security.custom.io/policy.md"
    custom_prefix = "https://raw.githubusercontent.com/JimmyOgb/custom-repo/"
    custom_evidence_url = "https://raw.githubusercontent.com/JimmyOgb/custom-repo/main/BuggyVault.sol"

    policy_token = "UNIQUE_SCOPE_TOKEN_RESTRICTED"
    evidence_token = "UNIQUE_VULNERABILITY_CODE_LINE_REENTRANCY"

    custom_policy_content = f"# Security Policy\nToken: {policy_token}\nIn-scope: BuggyVault.sol"
    custom_evidence_content = f"// Sol\nToken: {evidence_token}\ncontract BuggyVault {{}}"

    contract = direct_deploy(
        "contracts/bounty_arbiter.py",
        "0x" + direct_alice.hex(),
        custom_policy_url,
        custom_prefix,
    )
    direct_vm.sender = direct_alice

    direct_vm.clear_mocks()
    direct_vm.mock_web(
        r".*security\.custom\.io/policy\.md.*",
        {"status": 200, "body": custom_policy_content},
    )
    direct_vm.mock_web(
        r".*raw\.githubusercontent\.com/JimmyOgb/custom-repo/.*",
        {"status": 200, "body": custom_evidence_content},
    )

    # LLM mock ONLY matches if BOTH unique tokens are present in the prompt
    direct_vm.mock_llm(
        rf"(?s).*{policy_token}.*{evidence_token}.*",
        json.dumps({"valid": True, "severity": "HIGH", "rationale": "Grounded by policy and evidence"}),
    )

    rep_id = contract.submit_report(
        "0xAlice",
        custom_evidence_url,
        "Issue grounded in authoritative policy and code",
    )
    assert rep_id == 1
    assert direct_vm.run_validator() is True

    rep = contract.get_report(1)
    assert rep["valid"] is True
    assert rep["severity"] == "HIGH"
    assert rep["target_evidence_url"] == custom_evidence_url


def test_validator_rejection_validity_disagreement(direct_vm, direct_deploy, direct_alice):
    """
    Equivalence Principle: If the validator independently disagrees on validity,
    consensus MUST reject the transaction.
    """
    contract = direct_deploy(
        "contracts/bounty_arbiter.py",
        "0x" + direct_alice.hex(),
        DEFAULT_POLICY_URL,
        DEFAULT_TARGET_PREFIX,
    )
    direct_vm.sender = direct_alice

    # Leader sees a valid HIGH bug
    direct_vm.mock_llm(
        r".*",
        json.dumps({"valid": True, "severity": "HIGH", "rationale": "Vulnerability valid"}),
    )

    contract.submit_report(
        "0xResearcher",
        DEFAULT_EVIDENCE_URL,
        "Reward calculation rounding issue",
    )

    # Swap mock so validator independently evaluates report as invalid
    direct_vm.clear_mocks()
    mock_policy(direct_vm)
    mock_evidence(direct_vm)
    direct_vm.mock_llm(
        r".*",
        json.dumps({"valid": False, "severity": "NONE", "rationale": "Design limitation, not bug"}),
    )

    val_passed = direct_vm.run_validator()
    assert val_passed is False, "Validator must reject when validity disagrees"


def test_validator_rejection_adjacent_severity_mismatch(direct_vm, direct_deploy, direct_alice):
    """
    Strict Severity Equivalence: Any severity tier mismatch—including adjacent tiers
    (e.g., HIGH vs MEDIUM, CRITICAL vs HIGH)—MUST cause validator_fn to return False.
    """
    contract = direct_deploy(
        "contracts/bounty_arbiter.py",
        "0x" + direct_alice.hex(),
        DEFAULT_POLICY_URL,
        DEFAULT_TARGET_PREFIX,
    )
    direct_vm.sender = direct_alice

    adjacent_pairs = [
        ("HIGH", "MEDIUM"),
        ("CRITICAL", "HIGH"),
        ("MEDIUM", "LOW"),
    ]

    for leader_tier, validator_tier in adjacent_pairs:
        direct_vm.clear_mocks()
        mock_policy(direct_vm)
        mock_evidence(direct_vm)
        direct_vm.mock_llm(
            r".*",
            json.dumps({"valid": True, "severity": leader_tier, "rationale": f"Leader saw {leader_tier}"}),
        )

        contract.submit_report("0xResearcher", DEFAULT_EVIDENCE_URL, "Price feed latency manipulation")

        # Validator independently evaluates same report as adjacent tier
        direct_vm.clear_mocks()
        mock_policy(direct_vm)
        mock_evidence(direct_vm)
        direct_vm.mock_llm(
            r".*",
            json.dumps({"valid": True, "severity": validator_tier, "rationale": f"Validator saw {validator_tier}"}),
        )

        val_passed = direct_vm.run_validator()
        assert val_passed is False, f"Validator must reject adjacent mismatch: leader {leader_tier} vs validator {validator_tier}"


def test_validator_rejection_major_severity_divergence(direct_vm, direct_deploy, direct_alice):
    """
    Equivalence Principle: Major severity divergence (e.g. leader CRITICAL vs validator LOW)
    violates exact severity consensus and is rejected.
    """
    contract = direct_deploy(
        "contracts/bounty_arbiter.py",
        "0x" + direct_alice.hex(),
        DEFAULT_POLICY_URL,
        DEFAULT_TARGET_PREFIX,
    )
    direct_vm.sender = direct_alice

    # Leader evaluated report as CRITICAL
    direct_vm.mock_llm(
        r".*",
        json.dumps({"valid": True, "severity": "CRITICAL", "rationale": "Critical threat"}),
    )
    contract.submit_report("0xResearcher", DEFAULT_EVIDENCE_URL, "Price manipulation")

    # Validator independently evaluates same report as LOW
    direct_vm.clear_mocks()
    mock_policy(direct_vm)
    mock_evidence(direct_vm)
    direct_vm.mock_llm(
        r".*",
        json.dumps({"valid": True, "severity": "LOW", "rationale": "Minor edge case"}),
    )

    val_passed = direct_vm.run_validator()
    assert val_passed is False, "Validator must reject major severity tier divergences"


def test_validator_acceptance_exact_severity_match(direct_vm, direct_deploy, direct_alice):
    """
    Exact Binding: When leader and validator independently agree on the exact same
    severity tier and validity, consensus succeeds and locks the exact deterministic payout.
    """
    contract = direct_deploy(
        "contracts/bounty_arbiter.py",
        "0x" + direct_alice.hex(),
        DEFAULT_POLICY_URL,
        DEFAULT_TARGET_PREFIX,
    )
    direct_vm.sender = direct_alice

    expected_payouts = {
        "LOW": 100,
        "MEDIUM": 500,
        "HIGH": 2000,
        "CRITICAL": 5000,
    }

    for tier, payout in expected_payouts.items():
        direct_vm.clear_mocks()
        mock_policy(direct_vm)
        mock_evidence(direct_vm)
        direct_vm.mock_llm(
            r".*",
            json.dumps({"valid": True, "severity": tier, "rationale": f"Exact agreement on {tier}"}),
        )

        rep_id = contract.submit_report(f"0xResearcher_{tier}", DEFAULT_EVIDENCE_URL, f"Vulnerability {tier}")
        assert direct_vm.run_validator() is True

        rep = contract.get_report(rep_id)
        assert rep["valid"] is True
        assert rep["severity"] == tier
        assert rep["payout_due"] == payout


def test_validator_rejection_hallucinated_severity_tier(direct_vm, direct_deploy, direct_alice):
    contract = direct_deploy(
        "contracts/bounty_arbiter.py",
        "0x" + direct_alice.hex(),
        DEFAULT_POLICY_URL,
        DEFAULT_TARGET_PREFIX,
    )
    direct_vm.sender = direct_alice

    direct_vm.mock_llm(
        r".*",
        json.dumps({"valid": True, "severity": "HIGH", "rationale": "Valid issue"}),
    )
    contract.submit_report("0xResearcher", DEFAULT_EVIDENCE_URL, "Cross-chain relay bug")

    hallucinated_leader_result = {
        "valid": True,
        "severity": "SUPER_APOCALYPTIC_CRITICAL",
        "rationale": "Extreme catastrophic bug",
    }
    val_passed = direct_vm.run_validator(leader_result=hallucinated_leader_result)
    assert val_passed is False, "Validator must reject non-standard severity tiers"


def test_validator_rejection_semantic_contradiction(direct_vm, direct_deploy, direct_alice):
    contract = direct_deploy(
        "contracts/bounty_arbiter.py",
        "0x" + direct_alice.hex(),
        DEFAULT_POLICY_URL,
        DEFAULT_TARGET_PREFIX,
    )
    direct_vm.sender = direct_alice

    direct_vm.mock_llm(
        r".*",
        json.dumps({"valid": True, "severity": "HIGH", "rationale": "Valid issue"}),
    )
    contract.submit_report("0xResearcher", DEFAULT_EVIDENCE_URL, "Relay bug")

    # Contradiction 1: valid=False but severity="CRITICAL"
    bad_res_1 = {"valid": False, "severity": "CRITICAL", "rationale": "Invalid yet critical"}
    assert direct_vm.run_validator(leader_result=bad_res_1) is False

    # Contradiction 2: valid=True but severity="NONE"
    bad_res_2 = {"valid": True, "severity": "NONE", "rationale": "Valid yet no severity"}
    assert direct_vm.run_validator(leader_result=bad_res_2) is False


def test_validator_rejection_malformed_schema(direct_vm, direct_deploy, direct_alice):
    contract = direct_deploy(
        "contracts/bounty_arbiter.py",
        "0x" + direct_alice.hex(),
        DEFAULT_POLICY_URL,
        DEFAULT_TARGET_PREFIX,
    )
    direct_vm.sender = direct_alice

    direct_vm.mock_llm(
        r".*",
        json.dumps({"valid": True, "severity": "HIGH", "rationale": "Valid issue"}),
    )
    contract.submit_report("0xResearcher", DEFAULT_EVIDENCE_URL, "Relay bug")

    assert direct_vm.run_validator(leader_result={"severity": "HIGH", "rationale": "Missing valid"}) is False
    assert direct_vm.run_validator(leader_result={"valid": True, "rationale": "Missing severity"}) is False
    assert direct_vm.run_validator(leader_result={"valid": True, "severity": "HIGH"}) is False
    assert direct_vm.run_validator(leader_result="unexpected string result") is False


def test_claim_payout_flow(direct_vm, direct_deploy, direct_alice):
    contract = direct_deploy(
        "contracts/bounty_arbiter.py",
        "0x" + direct_alice.hex(),
        DEFAULT_POLICY_URL,
        DEFAULT_TARGET_PREFIX,
    )
    direct_vm.sender = direct_alice

    direct_vm.mock_llm(
        r".*",
        json.dumps({"valid": True, "severity": "HIGH", "rationale": "High severity finding"}),
    )

    rep_id = contract.submit_report("0xAlice", DEFAULT_EVIDENCE_URL, "Slippage bug")
    assert rep_id == 1

    claimed_amount = contract.claim_payout(1)
    assert claimed_amount == 2000

    rep = contract.get_report(1)
    assert rep["claimed"] is True


def test_claim_payout_gating_double_claim_reverts(direct_vm, direct_deploy, direct_alice):
    contract = direct_deploy(
        "contracts/bounty_arbiter.py",
        "0x" + direct_alice.hex(),
        DEFAULT_POLICY_URL,
        DEFAULT_TARGET_PREFIX,
    )
    direct_vm.sender = direct_alice

    direct_vm.mock_llm(
        r".*",
        json.dumps({"valid": True, "severity": "MEDIUM", "rationale": "Medium finding"}),
    )
    rep_id = contract.submit_report("0xAlice", DEFAULT_EVIDENCE_URL, "Issue")

    contract.claim_payout(rep_id)

    with direct_vm.expect_revert("Payout has already been claimed for this report"):
        contract.claim_payout(rep_id)


def test_claim_payout_gating_invalid_report_reverts(direct_vm, direct_deploy, direct_alice):
    contract = direct_deploy(
        "contracts/bounty_arbiter.py",
        "0x" + direct_alice.hex(),
        DEFAULT_POLICY_URL,
        DEFAULT_TARGET_PREFIX,
    )
    direct_vm.sender = direct_alice

    direct_vm.mock_llm(
        r".*",
        json.dumps({"valid": False, "severity": "NONE", "rationale": "Not a vulnerability"}),
    )
    rep_id = contract.submit_report("0xAlice", DEFAULT_EVIDENCE_URL, "Issue")

    with direct_vm.expect_revert("Cannot claim payout on invalid or rejected report"):
        contract.claim_payout(rep_id)


def test_claim_payout_nonexistent_report_reverts(direct_vm, direct_deploy, direct_alice):
    contract = direct_deploy(
        "contracts/bounty_arbiter.py",
        "0x" + direct_alice.hex(),
        DEFAULT_POLICY_URL,
        DEFAULT_TARGET_PREFIX,
    )
    direct_vm.sender = direct_alice

    with direct_vm.expect_revert("Report does not exist"):
        contract.claim_payout(999)

    with direct_vm.expect_revert("Report does not exist"):
        contract.claim_payout(0)


def test_submit_report_when_program_inactive_reverts(direct_vm, direct_deploy, direct_alice):
    owner_str = "0x" + direct_alice.hex()
    contract = direct_deploy(
        "contracts/bounty_arbiter.py",
        owner_str,
        DEFAULT_POLICY_URL,
        DEFAULT_TARGET_PREFIX,
    )
    direct_vm.sender = direct_alice

    contract.set_active(False)
    status = contract.get_program_status()
    assert status["is_active"] is False

    with direct_vm.expect_revert("Bounty program is currently paused or inactive"):
        contract.submit_report("0xResearcher", DEFAULT_EVIDENCE_URL, "Exploit details")


def test_submit_report_input_validation(direct_vm, direct_deploy, direct_alice):
    contract = direct_deploy(
        "contracts/bounty_arbiter.py",
        "0x" + direct_alice.hex(),
        DEFAULT_POLICY_URL,
        DEFAULT_TARGET_PREFIX,
    )
    direct_vm.sender = direct_alice

    with direct_vm.expect_revert("Researcher identity/address cannot be empty"):
        contract.submit_report("", DEFAULT_EVIDENCE_URL, "Bug details")

    with direct_vm.expect_revert("Target evidence URL cannot be empty"):
        contract.submit_report("0xResearcher", "", "Bug details")

    with direct_vm.expect_revert("Vulnerability details cannot be empty"):
        contract.submit_report("0xResearcher", DEFAULT_EVIDENCE_URL, "")


def test_administrative_methods_and_access_control(direct_vm, direct_deploy, direct_alice, direct_bob):
    owner_str = "0x" + direct_alice.hex()
    contract = direct_deploy(
        "contracts/bounty_arbiter.py",
        owner_str,
        DEFAULT_POLICY_URL,
        DEFAULT_TARGET_PREFIX,
    )

    # Owner updates payout table and configurations
    direct_vm.sender = direct_alice
    contract.update_payout("CRITICAL", 10000)
    contract.update_scope_policy("https://security.example.io/new-policy.md")
    contract.update_authoritative_target_prefix("https://raw.githubusercontent.com/JimmyOgb/new-repo/")

    status = contract.get_program_status()
    assert status["payout_table"]["CRITICAL"] == 10000
    assert status["scope_policy_url"] == "https://security.example.io/new-policy.md"
    assert status["authoritative_target_prefix"] == "https://raw.githubusercontent.com/JimmyOgb/new-repo/"

    # Non-owner attempts admin actions -> reverts
    direct_vm.sender = direct_bob
    with direct_vm.expect_revert("Only project owner can perform this action"):
        contract.set_active(False)

    with direct_vm.expect_revert("Only project owner can perform this action"):
        contract.update_payout("HIGH", 3000)

    with direct_vm.expect_revert("Only project owner can perform this action"):
        contract.update_scope_policy("https://hacked.com/policy.md")

    with direct_vm.expect_revert("Only project owner can perform this action"):
        contract.update_authoritative_target_prefix("https://evil.com/")
