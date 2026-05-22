"""
AccountFactory — creates AWS accounts via Organizations, moves them to target OUs,
applies baseline security controls (CloudTrail, Security Hub, budget alerts),
and tags accounts with owner metadata.
"""

import logging
import time
from dataclasses import dataclass
from typing import Any

import boto3
from botocore.exceptions import ClientError

logger = logging.getLogger(__name__)

POLL_INTERVAL_SECONDS = 10
MAX_CREATION_WAIT_SECONDS = 600  # 10 minutes


@dataclass
class AccountCreationResult:
    account_id: str
    account_name: str
    email: str
    ou_id: str
    request_id: str


class AccountFactory:
    """Vends new AWS accounts in Organizations with baseline governance applied."""

    def __init__(self, session: boto3.Session, management_account_id: str):
        self.session = session
        self.management_account_id = management_account_id
        self._org = session.client("organizations")
        self._sts = session.client("sts")

    def create_account(
        self,
        name: str,
        email: str,
        ou_id: str,
        tags: dict[str, str],
    ) -> AccountCreationResult:
        """
        Create a new AWS account in Organizations, wait for provisioning to complete,
        move it to the target OU, and tag it. Polls for up to 10 minutes.
        """
        logger.info("Creating account '%s' (%s) in OU %s", name, email, ou_id)
        tag_list = [{"Key": k, "Value": v} for k, v in tags.items()]

        create_resp = self._org.create_account(
            AccountName=name,
            Email=email,
            IamUserAccessToBilling="DENY",
            Tags=tag_list,
        )
        request_id = create_resp["CreateAccountStatus"]["Id"]
        logger.info("Account creation request submitted: %s", request_id)

        account_id = self._poll_creation_status(request_id)

        self.move_to_ou(account_id, ou_id)
        self.tag_account(account_id, tags)

        return AccountCreationResult(
            account_id=account_id,
            account_name=name,
            email=email,
            ou_id=ou_id,
            request_id=request_id,
        )

    def _poll_creation_status(self, request_id: str) -> str:
        """Poll CreateAccountStatus until SUCCEEDED or FAILED. Returns account_id."""
        deadline = time.time() + MAX_CREATION_WAIT_SECONDS
        while time.time() < deadline:
            resp = self._org.describe_create_account_status(
                CreateAccountRequestId=request_id
            )
            status = resp["CreateAccountStatus"]
            state = status["State"]

            if state == "SUCCEEDED":
                account_id = status["AccountId"]
                logger.info("Account creation succeeded: %s", account_id)
                return account_id

            if state == "FAILED":
                reason = status.get("FailureReason", "unknown")
                raise RuntimeError(
                    f"Account creation failed (request={request_id}): {reason}"
                )

            logger.debug(
                "Account creation state=%s, retrying in %ds...", state, POLL_INTERVAL_SECONDS
            )
            time.sleep(POLL_INTERVAL_SECONDS)

        raise TimeoutError(
            f"Account creation timed out after {MAX_CREATION_WAIT_SECONDS}s "
            f"(request_id={request_id})"
        )

    def move_to_ou(self, account_id: str, target_ou_id: str) -> None:
        """Move account from its current parent to the specified OU."""
        parents = self._org.list_parents(ChildId=account_id)["Parents"]
        if not parents:
            raise RuntimeError(f"No parent found for account {account_id}")

        source_parent_id = parents[0]["Id"]
        if source_parent_id == target_ou_id:
            logger.info("Account %s already in target OU %s", account_id, target_ou_id)
            return

        self._org.move_account(
            AccountId=account_id,
            SourceParentId=source_parent_id,
            DestinationParentId=target_ou_id,
        )
        logger.info("Moved account %s → OU %s", account_id, target_ou_id)

    def apply_baseline(self, account_id: str) -> None:
        """
        Assume OrganizationAccountAccessRole in the new account and:
          - Verify CloudTrail org trail coverage
          - Enable Security Hub with default standards
          - Create a budget alert at $100/month
        """
        member_session = self._assume_member_role(account_id)

        self._verify_cloudtrail(member_session, account_id)
        self._enable_security_hub(member_session, account_id)
        self._create_budget_alert(member_session, account_id)

    def _assume_member_role(self, account_id: str) -> boto3.Session:
        role_arn = f"arn:aws:iam::{account_id}:role/OrganizationAccountAccessRole"
        assumed = self._sts.assume_role(
            RoleArn=role_arn,
            RoleSessionName="account-factory-baseline",
        )
        creds = assumed["Credentials"]
        return boto3.Session(
            aws_access_key_id=creds["AccessKeyId"],
            aws_secret_access_key=creds["SecretAccessKey"],
            aws_session_token=creds["SessionToken"],
        )

    def _verify_cloudtrail(self, session: boto3.Session, account_id: str) -> None:
        ct = session.client("cloudtrail")
        trails = ct.describe_trails(includeShadowTrails=True).get("trailList", [])
        org_trails = [t for t in trails if t.get("IsOrganizationTrail")]
        if org_trails:
            logger.info(
                "Account %s covered by org trail(s): %s",
                account_id,
                [t["TrailARN"] for t in org_trails],
            )
        else:
            logger.warning(
                "No organization CloudTrail found in account %s; verify org trail is active",
                account_id,
            )

    def _enable_security_hub(self, session: boto3.Session, account_id: str) -> None:
        sh = session.client("securityhub")
        try:
            sh.enable_security_hub(
                Tags={"ManagedBy": "account-factory"},
                EnableDefaultStandards=True,
            )
            logger.info("Enabled Security Hub in account %s", account_id)
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            if code == "ResourceConflictException":
                logger.info("Security Hub already enabled in account %s", account_id)
            else:
                raise

    def _create_budget_alert(
        self,
        session: boto3.Session,
        account_id: str,
        limit_amount: str = "100.0",
        currency: str = "USD",
        alert_email: str | None = None,
    ) -> None:
        budgets = session.client("budgets")
        budget_name = "monthly-spend-alert"

        notifications_with_subscribers: list[dict] = [
            {
                "Notification": {
                    "NotificationType": "ACTUAL",
                    "ComparisonOperator": "GREATER_THAN",
                    "Threshold": 80.0,
                    "ThresholdType": "PERCENTAGE",
                    "NotificationState": "ALARM",
                },
                "Subscribers": [
                    {
                        "SubscriptionType": "EMAIL",
                        "Address": alert_email or f"billing+{account_id}@example.com",
                    }
                ],
            }
        ]

        try:
            budgets.create_budget(
                AccountId=account_id,
                Budget={
                    "BudgetName": budget_name,
                    "BudgetLimit": {"Amount": limit_amount, "Unit": currency},
                    "TimeUnit": "MONTHLY",
                    "BudgetType": "COST",
                },
                NotificationsWithSubscribers=notifications_with_subscribers,
            )
            logger.info(
                "Created budget alert '%s' ($%s/%s) in account %s",
                budget_name, limit_amount, currency, account_id,
            )
        except ClientError as exc:
            if exc.response["Error"]["Code"] == "DuplicateRecordException":
                logger.info("Budget '%s' already exists in account %s", budget_name, account_id)
            else:
                raise

    def tag_account(self, account_id: str, tags: dict[str, str]) -> None:
        """Apply or overwrite tags on the account resource in Organizations."""
        tag_list = [{"Key": k, "Value": v} for k, v in tags.items()]
        self._org.tag_resource(ResourceId=account_id, Tags=tag_list)
        logger.info("Tagged account %s with %d tag(s)", account_id, len(tag_list))

# _r 20260520150704-0355ad5d
