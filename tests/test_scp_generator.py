"""
pytest tests for SCPLoader validation, loading, and AccountFactory with moto.
"""

import json
import time
from pathlib import Path
from unittest.mock import MagicMock, patch

import boto3
import pytest

try:
    from moto import mock_organizations
except ImportError:
    pytest.skip("moto not installed", allow_module_level=True)

from lib.scp.loader import SCPLoader, SCPValidationError
from lib.vending.account_factory import AccountFactory


# ---------------------------------------------------------------------------
# Test fixtures and helpers
# ---------------------------------------------------------------------------

VALID_POLICY = {
    "Version": "2012-10-17",
    "Statement": [
        {
            "Sid": "DenyLeaveOrg",
            "Effect": "Deny",
            "Action": ["organizations:LeaveOrganization"],
            "Resource": "*",
        }
    ],
}

VALID_POLICY_MULTI = {
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Deny",
            "Action": ["s3:DeleteBucket", "s3:DeleteObject"],
            "Resource": "*",
        },
        {
            "Effect": "Allow",
            "Action": ["ec2:DescribeInstances"],
            "Resource": "*",
        },
    ],
}


def write_policy_file(directory: Path, name: str, policy: dict) -> Path:
    f = directory / f"{name}.json"
    f.write_text(json.dumps(policy, indent=2))
    return f


@pytest.fixture
def policy_dir(tmp_path: Path) -> Path:
    return tmp_path


@pytest.fixture
def loader() -> SCPLoader:
    return SCPLoader()


# ---------------------------------------------------------------------------
# SCPLoader.load_policy — valid cases
# ---------------------------------------------------------------------------


class TestLoadPolicyValid:
    def test_valid_policy_returns_dict(self, loader: SCPLoader, policy_dir: Path):
        f = write_policy_file(policy_dir, "deny-leave", VALID_POLICY)
        result = loader.load_policy(str(f))
        assert isinstance(result, dict)
        assert result["Version"] == "2012-10-17"

    def test_multi_statement_policy_loads(self, loader: SCPLoader, policy_dir: Path):
        f = write_policy_file(policy_dir, "multi-stmt", VALID_POLICY_MULTI)
        result = loader.load_policy(str(f))
        assert len(result["Statement"]) == 2

    def test_wildcard_action_is_valid(self, loader: SCPLoader, policy_dir: Path):
        policy = {
            "Version": "2012-10-17",
            "Statement": [{"Effect": "Deny", "Action": "*", "Resource": "*"}],
        }
        f = write_policy_file(policy_dir, "wildcard", policy)
        result = loader.load_policy(str(f))
        assert result["Statement"][0]["Action"] == "*"

    def test_notaction_is_accepted(self, loader: SCPLoader, policy_dir: Path):
        policy = {
            "Version": "2012-10-17",
            "Statement": [{"Effect": "Deny", "NotAction": ["sts:*"], "Resource": "*"}],
        }
        f = write_policy_file(policy_dir, "notaction", policy)
        result = loader.load_policy(str(f))
        assert "NotAction" in result["Statement"][0]


# ---------------------------------------------------------------------------
# SCPLoader.load_policy — invalid cases
# ---------------------------------------------------------------------------


class TestLoadPolicyInvalid:
    def test_file_not_found_raises(self, loader: SCPLoader):
        with pytest.raises(SCPValidationError, match="File not found"):
            loader.load_policy("/nonexistent/policy.json")

    def test_policy_exceeding_5120_chars_raises(self, loader: SCPLoader, policy_dir: Path):
        # Build a policy that exceeds 5120 characters
        big_actions = [f"service{i}:Action{i:04d}" for i in range(400)]
        policy = {
            "Version": "2012-10-17",
            "Statement": [{"Effect": "Deny", "Action": big_actions, "Resource": "*"}],
        }
        raw = json.dumps(policy, indent=2)
        # Ensure it actually exceeds limit
        if len(raw) <= 5120:
            big_actions = big_actions * 3
            policy["Statement"][0]["Action"] = big_actions
            raw = json.dumps(policy, indent=2)

        f = policy_dir / "large.json"
        f.write_text(raw)
        with pytest.raises(SCPValidationError, match="5120"):
            loader.load_policy(str(f))

    def test_missing_version_raises(self, loader: SCPLoader, policy_dir: Path):
        policy = {"Statement": [{"Effect": "Deny", "Action": "s3:*", "Resource": "*"}]}
        f = write_policy_file(policy_dir, "no-version", policy)
        with pytest.raises(SCPValidationError, match="Version"):
            loader.load_policy(str(f))

    def test_missing_statement_raises(self, loader: SCPLoader, policy_dir: Path):
        policy = {"Version": "2012-10-17"}
        f = write_policy_file(policy_dir, "no-stmt", policy)
        with pytest.raises(SCPValidationError, match="Statement"):
            loader.load_policy(str(f))

    def test_statement_not_list_raises(self, loader: SCPLoader, policy_dir: Path):
        policy = {
            "Version": "2012-10-17",
            "Statement": {"Effect": "Deny", "Action": "s3:*", "Resource": "*"},
        }
        f = write_policy_file(policy_dir, "stmt-obj", policy)
        with pytest.raises(SCPValidationError, match="list"):
            loader.load_policy(str(f))

    def test_invalid_effect_raises(self, loader: SCPLoader, policy_dir: Path):
        policy = {
            "Version": "2012-10-17",
            "Statement": [{"Effect": "Grant", "Action": "s3:*", "Resource": "*"}],
        }
        f = write_policy_file(policy_dir, "bad-effect", policy)
        with pytest.raises(SCPValidationError, match="Effect"):
            loader.load_policy(str(f))

    def test_missing_action_and_notaction_raises(self, loader: SCPLoader, policy_dir: Path):
        policy = {
            "Version": "2012-10-17",
            "Statement": [{"Effect": "Deny", "Resource": "*"}],
        }
        f = write_policy_file(policy_dir, "no-action", policy)
        with pytest.raises(SCPValidationError, match="Action"):
            loader.load_policy(str(f))

    def test_missing_resource_raises(self, loader: SCPLoader, policy_dir: Path):
        policy = {
            "Version": "2012-10-17",
            "Statement": [{"Effect": "Deny", "Action": "s3:*"}],
        }
        f = write_policy_file(policy_dir, "no-resource", policy)
        with pytest.raises(SCPValidationError, match="Resource"):
            loader.load_policy(str(f))

    def test_invalid_json_raises(self, loader: SCPLoader, policy_dir: Path):
        f = policy_dir / "bad.json"
        f.write_text("{not valid json{{")
        with pytest.raises(SCPValidationError, match="JSON"):
            loader.load_policy(str(f))


# ---------------------------------------------------------------------------
# SCPLoader.load_all
# ---------------------------------------------------------------------------


class TestLoadAll:
    def test_loads_multiple_policies(self, loader: SCPLoader, policy_dir: Path):
        write_policy_file(policy_dir, "deny-leave", VALID_POLICY)
        write_policy_file(policy_dir, "deny-s3", VALID_POLICY_MULTI)
        result = loader.load_all(str(policy_dir))
        assert "deny-leave" in result
        assert "deny-s3" in result
        assert len(result) == 2

    def test_returns_empty_dict_for_empty_dir(self, loader: SCPLoader, policy_dir: Path):
        result = loader.load_all(str(policy_dir))
        assert result == {}

    def test_raises_on_missing_directory(self, loader: SCPLoader):
        with pytest.raises(SCPValidationError):
            loader.load_all("/nonexistent/path")


# ---------------------------------------------------------------------------
# SCPLoader.compile_scp
# ---------------------------------------------------------------------------


class TestCompileScp:
    def test_compile_returns_compact_json(self, loader: SCPLoader):
        compiled = loader.compile_scp(VALID_POLICY)
        assert isinstance(compiled, str)
        assert " " not in compiled
        parsed = json.loads(compiled)
        assert parsed["Version"] == "2012-10-17"

    def test_compile_validates_size(self, loader: SCPLoader):
        big_actions = [f"svc{i}:Action{i}" for i in range(600)]
        policy = {
            "Version": "2012-10-17",
            "Statement": [{"Effect": "Deny", "Action": big_actions, "Resource": "*"}],
        }
        if len(json.dumps(policy, separators=(",", ":"))) > 5120:
            with pytest.raises(SCPValidationError, match="5120"):
                loader.compile_scp(policy)


# ---------------------------------------------------------------------------
# AccountFactory with moto
# ---------------------------------------------------------------------------


@mock_organizations
class TestAccountFactory:
    def _bootstrap_org(self) -> tuple[boto3.Session, str]:
        """Create an org and return (session, management_account_id)."""
        session = boto3.Session(region_name="us-east-1")
        org_client = session.client("organizations")
        org = org_client.create_organization(FeatureSet="ALL")
        mgmt_id = org["Organization"]["MasterAccountId"]
        return session, mgmt_id

    def test_create_account_succeeds(self):
        session, mgmt_id = self._bootstrap_org()
        factory = AccountFactory(session, mgmt_id)

        # Get root ID to use as target OU
        org_client = session.client("organizations")
        roots = org_client.list_roots()["Roots"]
        root_id = roots[0]["Id"]

        result = factory.create_account(
            name="test-dev-account",
            email="test-dev@example.com",
            ou_id=root_id,
            tags={"Environment": "dev", "Owner": "team-a"},
        )

        assert result.account_name == "test-dev-account"
        assert result.email == "test-dev@example.com"
        assert result.account_id is not None
        assert len(result.account_id) == 12

    def test_created_account_is_tagged(self):
        session, mgmt_id = self._bootstrap_org()
        factory = AccountFactory(session, mgmt_id)

        org_client = session.client("organizations")
        root_id = org_client.list_roots()["Roots"][0]["Id"]

        tags = {"Environment": "staging", "CostCenter": "cc-123"}
        result = factory.create_account(
            name="tagged-account",
            email="tagged@example.com",
            ou_id=root_id,
            tags=tags,
        )

        aws_tags = org_client.list_tags_for_resource(ResourceId=result.account_id)["Tags"]
        tag_dict = {t["Key"]: t["Value"] for t in aws_tags}
        assert tag_dict.get("Environment") == "staging"
        assert tag_dict.get("CostCenter") == "cc-123"

    def test_move_to_ou(self):
        session, mgmt_id = self._bootstrap_org()
        factory = AccountFactory(session, mgmt_id)

        org_client = session.client("organizations")
        root_id = org_client.list_roots()["Roots"][0]["Id"]

        # Create a target OU
        target_ou = org_client.create_organizational_unit(
            ParentId=root_id, Name="workloads"
        )["OrganizationalUnit"]["Id"]

        result = factory.create_account(
            name="move-test",
            email="move@example.com",
            ou_id=root_id,
            tags={},
        )

        # Move to the new OU
        factory.move_to_ou(result.account_id, target_ou)
        parents = org_client.list_parents(ChildId=result.account_id)["Parents"]
        assert parents[0]["Id"] == target_ou

# _r 20260625150408-40894754
