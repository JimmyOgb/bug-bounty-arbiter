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


def test_initialization_insecure_policy_url_reverts(direct_vm, direct_deploy):
    with direct_vm.expect_revert("scheme must be https"):
        direct_deploy(
            "contracts/bounty_arbiter.py",
            "0xOwner",
            "http://security.example.io/policy.md",
            DEFAULT_TARGET_PREFIX,
        )


def test_initialization_insecure_target_prefix_reverts(direct_vm, direct_deploy):
    with direct_vm.expect_revert("scheme must be https"):
        direct_deploy(
            "contracts/bounty_arbiter.py",
            "0xOwner",
            DEFAULT_POLICY_URL,
            "http://raw.githubusercontent.com/JimmyOgb/bug-bounty-arbiter/",
        )



def test_evidence_url_authority_boundary_validation(direct_vm, direct_deploy, direct_alice):
    """
    Robust Parsed Origin & Path-Boundary Validation:
    Rejects lookalike domains, domain typos, insecure schemes, lookalike path prefixes,
    credentials/userinfo, query strings, and path traversal elements.
    """
    contract = direct_deploy(
        "contracts/bounty_arbiter.py",
        "0x" + direct_alice.hex(),
        DEFAULT_POLICY_URL,
        DEFAULT_TARGET_PREFIX,
    )
    direct_vm.sender = direct_alice

    unauthorized_urls = [
        # External / unauthorized domains
        "https://attacker.evil.com/fake_proof.sol",
        "https://raw.githubusercontent.com/MaliciousActor/exploit/main.sol",
        "https://pastebin.com/raw/exploit",
        # Lookalike domain attacks
        "https://raw.githubusercontent.com.attacker.com/JimmyOgb/bug-bounty-arbiter/main/VaultCore.sol",
        "https://raw.githubusercontent.evil.com/JimmyOgb/bug-bounty-arbiter/main/VaultCore.sol",
        # Domain typos
        "https://raw.githybusercontent.com/JimmyOgb/bug-bounty-arbiter/main/VaultCore.sol",
        "https://raw.githubbusercontent.com/JimmyOgb/bug-bounty-arbiter/main/VaultCore.sol",
        # Insecure scheme (http)
        "http://raw.githubusercontent.com/JimmyOgb/bug-bounty-arbiter/main/contracts/VaultCore.sol",
        # Lookalike path prefixes (same root name without delimiter)
        "https://raw.githubusercontent.com/JimmyOgb/bug-bounty-arbiter-fake/main/contracts/VaultCore.sol",
        "https://raw.githubusercontent.com/JimmyOgb/bug-bounty-arbiter_phishing/main/contracts/VaultCore.sol",
        "https://raw.githubusercontent.com/JimmyOgb/bug-bounty-arbiter-clone/main/contracts/VaultCore.sol",
        # Query string injection
        "https://raw.githubusercontent.com/JimmyOgb/bug-bounty-arbiter/main/contracts/VaultCore.sol?token=secret",
        # Embedded credentials / userinfo
        "https://attacker:secret@raw.githubusercontent.com/JimmyOgb/bug-bounty-arbiter/main/contracts/VaultCore.sol",
        # Path traversal elements
        "https://raw.githubusercontent.com/JimmyOgb/bug-bounty-arbiter/../../evil/exploit.sol",
        "https://raw.githubusercontent.com/JimmyOgb/bug-bounty-arbiter/%2e%2e/evil/exploit.sol",
    ]

    for unauth_url in unauthorized_urls:
        with direct_vm.expect_revert("Evidence URL violates authoritative domain boundary"):
            contract.submit_report(
                unauth_url,
                "Exploit details pointing outside authoritative boundary",
            )

    status = contract.get_program_status()
    assert status["total_submissions"] == 0


def test_authenticated_submitter_binding(direct_vm, direct_deploy, direct_alice, direct_bob):
    """
    Secure Submitter Binding:
    Reports are automatically bound to the transaction caller (gl.message.sender).
    Callers cannot spoof the researcher identity.
    """
    contract = direct_deploy(
        "contracts/bounty_arbiter.py",
        "0x" + direct_alice.hex(),
        DEFAULT_POLICY_URL,
        DEFAULT_TARGET_PREFIX,
    )

    llm_payload = {
        "valid": True,
        "severity": "HIGH",
        "rationale": "High severity finding bound to caller.",
    }
    direct_vm.mock_llm(r".*", json.dumps(llm_payload))

    # 1. Alice submits report #1
    direct_vm.sender = direct_alice
    rep_id_1 = contract.submit_report(
        DEFAULT_EVIDENCE_URL,
        "Vulnerability found by Alice.",
    )
    assert rep_id_1 == 1

    report_1 = contract.get_report(1)
    assert report_1["researcher"].lower() == ("0x" + direct_alice.hex()).lower()
    adjudicated_1 = contract.get_adjudicated_report(1)
    assert str(adjudicated_1.researcher).lower() == ("0x" + direct_alice.hex()).lower()

    # 2. Bob submits report #2
    direct_vm.sender = direct_bob
    rep_id_2 = contract.submit_report(
        DEFAULT_EVIDENCE_URL,
        "Vulnerability found by Bob.",
    )
    assert rep_id_2 == 2

    report_2 = contract.get_report(2)
    assert report_2["researcher"].lower() == ("0x" + direct_bob.hex()).lower()
    adjudicated_2 = contract.get_adjudicated_report(2)
    assert str(adjudicated_2.researcher).lower() == ("0x" + direct_bob.hex()).lower()


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
    assert report["researcher"].lower() == ("0x" + direct_alice.hex()).lower()
    assert report["target_evidence_url"] == DEFAULT_EVIDENCE_URL
    assert report["valid"] is True
    assert report["severity"] == "CRITICAL"
    assert report["rationale"] == "Reentrancy in withdrawAll() allows full pool drain."
    assert report["recommended_payout_units"] == 5000
    assert "claimed" not in report

    # Check get_adjudicated_report interface
    adjudicated = contract.get_adjudicated_report(1)
    assert int(adjudicated.id) == 1
    assert str(adjudicated.researcher).lower() == ("0x" + direct_alice.hex()).lower()
    assert adjudicated.valid is True
    assert adjudicated.severity == "CRITICAL"
    assert int(adjudicated.recommended_payout_units) == 5000

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
            DEFAULT_EVIDENCE_URL,
            f"Technical report details for {tier}",
        )
        assert rep_id == idx

        val_ok = direct_vm.run_validator()
        assert val_ok is True

        rep = contract.get_report(rep_id)
        assert rep["valid"] is True
        assert rep["severity"] == tier
        assert rep["recommended_payout_units"] == expected_payout
        assert "claimed" not in rep

        adj = contract.get_adjudicated_report(rep_id)
        assert adj.valid is True
        assert adj.severity == tier
        assert int(adj.recommended_payout_units) == expected_payout


def test_submit_report_invalid_creates_no_payout_liability(direct_vm, direct_deploy, direct_alice):
    """
    Submitting an invalid report results in valid=False, severity=NONE, recommended_payout_units=0.
    No payout recommendation is certified.
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
        DEFAULT_EVIDENCE_URL,
        "Token can be transferred to any address.",
    )
    assert report_id == 1

    val_passed = direct_vm.run_validator()
    assert val_passed is True

    report = contract.get_report(1)
    assert report["valid"] is False
    assert report["severity"] == "NONE"
    assert report["recommended_payout_units"] == 0
    assert "claimed" not in report

    adj = contract.get_adjudicated_report(1)
    assert adj.valid is False
    assert adj.severity == "NONE"
    assert int(adj.recommended_payout_units) == 0


def test_fail_closed_policy_fetch_http_error(direct_vm, direct_deploy, direct_alice):
    """
    Fail-Closed Gate: If scope policy fetch returns non-200 (404/500), execution immediately reverts
    before any report state is recorded.
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
        contract.submit_report(DEFAULT_EVIDENCE_URL, "Bug details")

    # Mock HTTP 500 failure on policy
    direct_vm.clear_mocks()
    mock_policy(direct_vm, status=500, body="Internal Server Error")
    mock_evidence(direct_vm, status=200, body=DEFAULT_EVIDENCE_BODY)

    with direct_vm.expect_revert("Failed to acquire authoritative scope policy or target evidence; failing closed."):
        contract.submit_report(DEFAULT_EVIDENCE_URL, "Bug details")

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
        contract.submit_report(DEFAULT_EVIDENCE_URL, "Bug details")

    assert contract.get_program_status()["total_submissions"] == 0


def test_fail_closed_evidence_fetch_http_error(direct_vm, direct_deploy, direct_alice):
    """
    Fail-Closed Gate: If target evidence fetch returns non-200 (404/500), execution immediately reverts
    before any report state is recorded.
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
        contract.submit_report(DEFAULT_EVIDENCE_URL, "Bug details")

    # Mock HTTP 500 failure on evidence
    direct_vm.clear_mocks()
    mock_policy(direct_vm, status=200, body=DEFAULT_POLICY_BODY)
    mock_evidence(direct_vm, status=500, body="Internal Server Error")

    with direct_vm.expect_revert("Failed to acquire authoritative scope policy or target evidence; failing closed."):
        contract.submit_report(DEFAULT_EVIDENCE_URL, "Bug details")

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
        contract.submit_report(DEFAULT_EVIDENCE_URL, "Bug details")

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
        contract.submit_report(DEFAULT_EVIDENCE_URL, "Bug details")

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

        contract.submit_report(DEFAULT_EVIDENCE_URL, "Price feed latency manipulation")

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
    contract.submit_report(DEFAULT_EVIDENCE_URL, "Price manipulation")

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
    severity tier and validity, consensus succeeds and locks the exact deterministic recommended units.
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

        rep_id = contract.submit_report(DEFAULT_EVIDENCE_URL, f"Vulnerability {tier}")
        assert direct_vm.run_validator() is True

        rep = contract.get_report(rep_id)
        assert rep["valid"] is True
        assert rep["severity"] == tier
        assert rep["recommended_payout_units"] == payout

        adj = contract.get_adjudicated_report(rep_id)
        assert adj.valid is True
        assert adj.severity == tier
        assert int(adj.recommended_payout_units) == payout


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
    contract.submit_report(DEFAULT_EVIDENCE_URL, "Cross-chain relay bug")

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
    contract.submit_report(DEFAULT_EVIDENCE_URL, "Relay bug")

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
    contract.submit_report(DEFAULT_EVIDENCE_URL, "Relay bug")

    assert direct_vm.run_validator(leader_result={"severity": "HIGH", "rationale": "Missing valid"}) is False
    assert direct_vm.run_validator(leader_result={"valid": True, "rationale": "Missing severity"}) is False
    assert direct_vm.run_validator(leader_result={"valid": True, "severity": "HIGH"}) is False
    assert direct_vm.run_validator(leader_result="unexpected string result") is False


def test_adjudicated_report_metadata_oracle_primitive(direct_vm, direct_deploy, direct_alice):
    """
    Adjudication Arbiter & Oracle Primitive:
    Contract certifies report validity and recommended units as immutable adjudication metadata.
    There is no hollow claim_payout write method or claimed flag.
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
        json.dumps({"valid": True, "severity": "HIGH", "rationale": "High severity finding"}),
    )

    rep_id = contract.submit_report(DEFAULT_EVIDENCE_URL, "Slippage bug")
    assert rep_id == 1

    # Verify get_adjudicated_report read interface for downstream consumers
    adjudicated = contract.get_adjudicated_report(1)
    assert int(adjudicated.id) == 1
    assert str(adjudicated.researcher).lower() == ("0x" + direct_alice.hex()).lower()
    assert adjudicated.target_evidence_url == DEFAULT_EVIDENCE_URL
    assert adjudicated.valid is True
    assert adjudicated.severity == "HIGH"
    assert adjudicated.rationale == "High severity finding"
    assert int(adjudicated.recommended_payout_units) == 2000

    # Ensure claim_payout write method is completely removed
    assert not hasattr(contract, "claim_payout"), "claim_payout method must be removed"

    # Ensure get_report contains clean adjudication metadata without dead claimed flag
    report = contract.get_report(1)
    assert "claimed" not in report
    assert report["recommended_payout_units"] == 2000


def test_adjudication_metadata_immutability_and_clean_queries(direct_vm, direct_deploy, direct_alice, direct_bob):
    """
    Verify multiple submissions produce distinct immutable metadata records, and queries
    contain clean metadata without dead claim paths.
    """
    contract = direct_deploy(
        "contracts/bounty_arbiter.py",
        "0x" + direct_alice.hex(),
        DEFAULT_POLICY_URL,
        DEFAULT_TARGET_PREFIX,
    )

    # 1. Alice report (MEDIUM)
    direct_vm.sender = direct_alice
    direct_vm.mock_llm(
        r".*",
        json.dumps({"valid": True, "severity": "MEDIUM", "rationale": "Medium finding"}),
    )
    rep_1 = contract.submit_report(DEFAULT_EVIDENCE_URL, "Medium issue")

    # 2. Bob report (CRITICAL)
    direct_vm.sender = direct_bob
    direct_vm.clear_mocks()
    mock_policy(direct_vm)
    mock_evidence(direct_vm)
    direct_vm.mock_llm(
        r".*",
        json.dumps({"valid": True, "severity": "CRITICAL", "rationale": "Critical finding"}),
    )
    rep_2 = contract.submit_report(DEFAULT_EVIDENCE_URL, "Critical issue")

    # Verify Report 1
    adj_1 = contract.get_adjudicated_report(rep_1)
    assert int(adj_1.id) == 1
    assert str(adj_1.researcher).lower() == ("0x" + direct_alice.hex()).lower()
    assert adj_1.severity == "MEDIUM"
    assert int(adj_1.recommended_payout_units) == 500

    # Verify Report 2
    adj_2 = contract.get_adjudicated_report(rep_2)
    assert int(adj_2.id) == 2
    assert str(adj_2.researcher).lower() == ("0x" + direct_bob.hex()).lower()
    assert adj_2.severity == "CRITICAL"
    assert int(adj_2.recommended_payout_units) == 5000


def test_adjudication_metadata_invalid_report_zero_units(direct_vm, direct_deploy, direct_alice):
    """Invalid report sets recommended units to 0 and valid to False."""
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
    rep_id = contract.submit_report(DEFAULT_EVIDENCE_URL, "Non-issue")

    adj = contract.get_adjudicated_report(rep_id)
    assert adj.valid is False
    assert adj.severity == "NONE"
    assert int(adj.recommended_payout_units) == 0


def test_get_adjudicated_report_nonexistent_reverts(direct_vm, direct_deploy, direct_alice):
    """Querying non-existent report IDs reverts safely."""
    contract = direct_deploy(
        "contracts/bounty_arbiter.py",
        "0x" + direct_alice.hex(),
        DEFAULT_POLICY_URL,
        DEFAULT_TARGET_PREFIX,
    )
    direct_vm.sender = direct_alice

    with direct_vm.expect_revert("Report does not exist"):
        contract.get_adjudicated_report(999)

    with direct_vm.expect_revert("Report does not exist"):
        contract.get_adjudicated_report(0)


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
        contract.submit_report(DEFAULT_EVIDENCE_URL, "Exploit details")


def test_submit_report_input_validation(direct_vm, direct_deploy, direct_alice):
    contract = direct_deploy(
        "contracts/bounty_arbiter.py",
        "0x" + direct_alice.hex(),
        DEFAULT_POLICY_URL,
        DEFAULT_TARGET_PREFIX,
    )
    direct_vm.sender = direct_alice

    with direct_vm.expect_revert("Target evidence URL cannot be empty"):
        contract.submit_report("", "Bug details")

    with direct_vm.expect_revert("Vulnerability details cannot be empty"):
        contract.submit_report(DEFAULT_EVIDENCE_URL, "")


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

    # Insecure URL updates revert
    with direct_vm.expect_revert("scheme must be https"):
        contract.update_scope_policy("http://insecure.example.io/policy.md")

    with direct_vm.expect_revert("scheme must be https"):
        contract.update_authoritative_target_prefix("http://raw.githubusercontent.com/JimmyOgb/new-repo/")

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
