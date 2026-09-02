import json
import pytest


def test_initialization_and_program_status(direct_vm, direct_deploy, direct_alice):
    owner = "0x" + direct_alice.hex()
    policy_url = "https://security.example.io/bounty-policy.md"

    contract = direct_deploy("contracts/bounty_arbiter.py", owner, policy_url)
    status = contract.get_program_status()

    assert status["project_owner"] == owner
    assert status["scope_policy_url"] == policy_url
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
        direct_deploy("contracts/bounty_arbiter.py", "", "https://example.com/policy")


def test_initialization_empty_policy_url_reverts(direct_vm, direct_deploy):
    with direct_vm.expect_revert("Scope policy URL cannot be empty"):
        direct_deploy("contracts/bounty_arbiter.py", "0xOwner", "")


def test_submit_report_valid_critical(direct_vm, direct_deploy, direct_alice):
    contract = direct_deploy(
        "contracts/bounty_arbiter.py",
        "0x" + direct_alice.hex(),
        "https://security.example.io/policy.md",
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
        "VaultCore.sol",
        "Reentrancy vector identified via cross-function state update desync.",
    )
    assert report_id == 1

    # Multi-validator consensus verification
    val_passed = direct_vm.run_validator()
    assert val_passed is True

    # Check on-chain stored metadata
    report = contract.get_report(1)
    assert report["id"] == 1
    assert report["researcher"] == "0xResearcher1"
    assert report["target_component"] == "VaultCore.sol"
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
        "https://security.example.io/policy.md",
    )
    direct_vm.sender = direct_alice

    tiers = [
        ("HIGH", 2000, "Oracle latency manipulation"),
        ("MEDIUM", 500, "Unbounded loop denial-of-service in batchTransfer"),
        ("LOW", 100, "Inaccurate event emission on fee update"),
    ]

    for idx, (tier, expected_payout, rationale) in enumerate(tiers, start=1):
        direct_vm.clear_mocks()
        direct_vm.mock_llm(
            r".*",
            json.dumps({"valid": True, "severity": tier, "rationale": rationale}),
        )

        rep_id = contract.submit_report(
            f"0xResearcher_{tier}",
            f"Component_{tier}.sol",
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


def test_submit_report_invalid_spam(direct_vm, direct_deploy, direct_alice):
    contract = direct_deploy(
        "contracts/bounty_arbiter.py",
        "0x" + direct_alice.hex(),
        "https://security.example.io/policy.md",
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
        "GovernanceToken.sol",
        "Token can be transferred to any address.",
    )
    assert report_id == 1

    # Validator consensus succeeds on invalid report
    val_passed = direct_vm.run_validator()
    assert val_passed is True

    report = contract.get_report(1)
    assert report["valid"] is False
    assert report["severity"] == "NONE"
    assert report["payout_due"] == 0
    assert report["claimed"] is False


def test_validator_rejection_validity_disagreement(direct_vm, direct_deploy, direct_alice):
    """
    Equivalence Principle: If the validator independently disagrees on validity,
    consensus MUST reject the transaction.
    """
    contract = direct_deploy(
        "contracts/bounty_arbiter.py",
        "0x" + direct_alice.hex(),
        "https://security.example.io/policy.md",
    )
    direct_vm.sender = direct_alice

    # Leader sees a valid HIGH bug
    direct_vm.mock_llm(
        r".*",
        json.dumps({"valid": True, "severity": "HIGH", "rationale": "Vulnerability valid"}),
    )

    contract.submit_report(
        "0xResearcher",
        "Staking.sol",
        "Reward calculation rounding issue",
    )

    # Swap mock so validator independently evaluates report as invalid
    direct_vm.clear_mocks()
    direct_vm.mock_llm(
        r".*",
        json.dumps({"valid": False, "severity": "NONE", "rationale": "Design limitation, not bug"}),
    )

    val_passed = direct_vm.run_validator()
    assert val_passed is False, "Validator must reject when validity disagrees"


def test_validator_rejection_hallucinated_severity_tier(direct_vm, direct_deploy, direct_alice):
    """
    Equivalence Principle: If the leader hallucinates a non-standard tier,
    the validator MUST reject the transaction.
    """
    contract = direct_deploy(
        "contracts/bounty_arbiter.py",
        "0x" + direct_alice.hex(),
        "https://security.example.io/policy.md",
    )
    direct_vm.sender = direct_alice

    direct_vm.mock_llm(
        r".*",
        json.dumps({"valid": True, "severity": "HIGH", "rationale": "Valid issue"}),
    )
    contract.submit_report("0xResearcher", "Bridge.sol", "Cross-chain relay bug")

    # Simulate leader returning an invalid hallucinated tier
    hallucinated_leader_result = {
        "valid": True,
        "severity": "SUPER_APOCALYPTIC_CRITICAL",
        "rationale": "Extreme catastrophic bug",
    }
    val_passed = direct_vm.run_validator(leader_result=hallucinated_leader_result)
    assert val_passed is False, "Validator must reject non-standard severity tiers"


def test_validator_rejection_semantic_contradiction(direct_vm, direct_deploy, direct_alice):
    """
    Validator rejects if leader proposes invalid=False but severity is not NONE,
    or valid=True with severity=NONE.
    """
    contract = direct_deploy(
        "contracts/bounty_arbiter.py",
        "0x" + direct_alice.hex(),
        "https://security.example.io/policy.md",
    )
    direct_vm.sender = direct_alice

    direct_vm.mock_llm(
        r".*",
        json.dumps({"valid": True, "severity": "HIGH", "rationale": "Valid issue"}),
    )
    contract.submit_report("0xResearcher", "Bridge.sol", "Relay bug")

    # Contradiction 1: valid=False but severity="CRITICAL"
    bad_res_1 = {"valid": False, "severity": "CRITICAL", "rationale": "Invalid yet critical"}
    assert direct_vm.run_validator(leader_result=bad_res_1) is False

    # Contradiction 2: valid=True but severity="NONE"
    bad_res_2 = {"valid": True, "severity": "NONE", "rationale": "Valid yet no severity"}
    assert direct_vm.run_validator(leader_result=bad_res_2) is False


def test_validator_rejection_malformed_schema(direct_vm, direct_deploy, direct_alice):
    """
    Validator rejects transactions where leader return value violates schema.
    """
    contract = direct_deploy(
        "contracts/bounty_arbiter.py",
        "0x" + direct_alice.hex(),
        "https://security.example.io/policy.md",
    )
    direct_vm.sender = direct_alice

    direct_vm.mock_llm(
        r".*",
        json.dumps({"valid": True, "severity": "HIGH", "rationale": "Valid issue"}),
    )
    contract.submit_report("0xResearcher", "Bridge.sol", "Relay bug")

    # Missing "valid" field
    assert direct_vm.run_validator(leader_result={"severity": "HIGH", "rationale": "Missing valid"}) is False

    # Missing "severity" field
    assert direct_vm.run_validator(leader_result={"valid": True, "rationale": "Missing severity"}) is False

    # Missing "rationale" field
    assert direct_vm.run_validator(leader_result={"valid": True, "severity": "HIGH"}) is False

    # Non-dictionary payload
    assert direct_vm.run_validator(leader_result="unexpected string result") is False


def test_validator_rejection_major_severity_divergence(direct_vm, direct_deploy, direct_alice):
    """
    Equivalence Principle: Major severity divergence (e.g. leader CRITICAL vs validator LOW)
    violates consensus tolerance and is rejected.
    """
    contract = direct_deploy(
        "contracts/bounty_arbiter.py",
        "0x" + direct_alice.hex(),
        "https://security.example.io/policy.md",
    )
    direct_vm.sender = direct_alice

    # Leader evaluated report as CRITICAL
    direct_vm.mock_llm(
        r".*",
        json.dumps({"valid": True, "severity": "CRITICAL", "rationale": "Critical threat"}),
    )
    contract.submit_report("0xResearcher", "Oracle.sol", "Price manipulation")

    # Validator independently evaluates same report as LOW (tier difference = 3 > 1)
    direct_vm.clear_mocks()
    direct_vm.mock_llm(
        r".*",
        json.dumps({"valid": True, "severity": "LOW", "rationale": "Minor edge case"}),
    )

    val_passed = direct_vm.run_validator()
    assert val_passed is False, "Validator must reject major severity tier divergences"


def test_claim_payout_flow(direct_vm, direct_deploy, direct_alice):
    contract = direct_deploy(
        "contracts/bounty_arbiter.py",
        "0x" + direct_alice.hex(),
        "https://security.example.io/policy.md",
    )
    direct_vm.sender = direct_alice

    direct_vm.mock_llm(
        r".*",
        json.dumps({"valid": True, "severity": "HIGH", "rationale": "High severity finding"}),
    )

    rep_id = contract.submit_report("0xAlice", "DexRouter.sol", "Slippage bug")
    assert rep_id == 1

    # Claim payout
    claimed_amount = contract.claim_payout(1)
    assert claimed_amount == 2000

    # Verify state reflects claimed status
    rep = contract.get_report(1)
    assert rep["claimed"] is True


def test_claim_payout_gating_double_claim_reverts(direct_vm, direct_deploy, direct_alice):
    contract = direct_deploy(
        "contracts/bounty_arbiter.py",
        "0x" + direct_alice.hex(),
        "https://security.example.io/policy.md",
    )
    direct_vm.sender = direct_alice

    direct_vm.mock_llm(
        r".*",
        json.dumps({"valid": True, "severity": "MEDIUM", "rationale": "Medium finding"}),
    )
    rep_id = contract.submit_report("0xAlice", "Token.sol", "Issue")

    contract.claim_payout(rep_id)

    with direct_vm.expect_revert("Payout has already been claimed for this report"):
        contract.claim_payout(rep_id)


def test_claim_payout_gating_invalid_report_reverts(direct_vm, direct_deploy, direct_alice):
    contract = direct_deploy(
        "contracts/bounty_arbiter.py",
        "0x" + direct_alice.hex(),
        "https://security.example.io/policy.md",
    )
    direct_vm.sender = direct_alice

    direct_vm.mock_llm(
        r".*",
        json.dumps({"valid": False, "severity": "NONE", "rationale": "Not a vulnerability"}),
    )
    rep_id = contract.submit_report("0xAlice", "Token.sol", "Issue")

    with direct_vm.expect_revert("Cannot claim payout on invalid or rejected report"):
        contract.claim_payout(rep_id)


def test_claim_payout_nonexistent_report_reverts(direct_vm, direct_deploy, direct_alice):
    contract = direct_deploy(
        "contracts/bounty_arbiter.py",
        "0x" + direct_alice.hex(),
        "https://security.example.io/policy.md",
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
        "https://security.example.io/policy.md",
    )
    direct_vm.sender = direct_alice

    # Owner pauses program
    contract.set_active(False)
    status = contract.get_program_status()
    assert status["is_active"] is False

    with direct_vm.expect_revert("Bounty program is currently paused or inactive"):
        contract.submit_report("0xResearcher", "Vault.sol", "Exploit details")


def test_submit_report_input_validation(direct_vm, direct_deploy, direct_alice):
    contract = direct_deploy(
        "contracts/bounty_arbiter.py",
        "0x" + direct_alice.hex(),
        "https://security.example.io/policy.md",
    )
    direct_vm.sender = direct_alice

    with direct_vm.expect_revert("Researcher identity/address cannot be empty"):
        contract.submit_report("", "Vault.sol", "Bug details")

    with direct_vm.expect_revert("Target component cannot be empty"):
        contract.submit_report("0xResearcher", "", "Bug details")

    with direct_vm.expect_revert("Vulnerability details cannot be empty"):
        contract.submit_report("0xResearcher", "Vault.sol", "")


def test_administrative_methods_and_access_control(direct_vm, direct_deploy, direct_alice, direct_bob):
    owner_str = "0x" + direct_alice.hex()
    contract = direct_deploy(
        "contracts/bounty_arbiter.py",
        owner_str,
        "https://security.example.io/policy.md",
    )

    # Owner updates payout table
    direct_vm.sender = direct_alice
    contract.update_payout("CRITICAL", 10000)
    contract.update_scope_policy("https://security.example.io/new-policy.md")

    status = contract.get_program_status()
    assert status["payout_table"]["CRITICAL"] == 10000
    assert status["scope_policy_url"] == "https://security.example.io/new-policy.md"

    # Non-owner attempts admin actions -> reverts
    direct_vm.sender = direct_bob
    with direct_vm.expect_revert("Only project owner can perform this action"):
        contract.set_active(False)

    with direct_vm.expect_revert("Only project owner can perform this action"):
        contract.update_payout("HIGH", 3000)

    with direct_vm.expect_revert("Only project owner can perform this action"):
        contract.update_scope_policy("https://hacked.com/policy.md")
