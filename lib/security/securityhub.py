"""
SecurityHubManager — enables Security Hub delegated admin, subscribes accounts
to compliance standards, fetches findings with severity/workflow filters, and
aggregates findings by compliance control ID.
"""

import logging
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Any

import boto3
from botocore.exceptions import ClientError

logger = logging.getLogger(__name__)

SEVERITY_LABELS = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFORMATIONAL"]

CIS_STANDARD_ARN = (
    "arn:aws:securityhub:us-east-1::standards/cis-aws-foundations-benchmark/v/1.4.0"
)
PCI_STANDARD_ARN = (
    "arn:aws:securityhub:us-east-1::standards/pci-dss/v/3.2.1"
)
AWS_FOUNDATIONAL_STANDARD_ARN = (
    "arn:aws:securityhub:us-east-1::standards/aws-foundational-security-best-practices/v/1.0.0"
)


@dataclass
class SecurityHubFinding:
    finding_id: str
    title: str
    severity: str
    status: str
    workflow_status: str
    account_id: str
    region: str
    resource_arn: str
    control_id: str
    updated_at: str


@dataclass
class ControlSummary:
    control_id: str
    title: str
    passed: int = 0
    failed: int = 0
    suppressed: int = 0

    @property
    def total(self) -> int:
        return self.passed + self.failed + self.suppressed

    @property
    def pass_rate(self) -> float:
        return (self.passed / self.total * 100) if self.total > 0 else 0.0


class SecurityHubManager:
    """Manages Security Hub across AWS organization accounts."""

    def __init__(self, session: boto3.Session):
        self.session = session
        self._sh = session.client("securityhub")
        self._org = session.client("organizations")

    def enable_delegated_admin(self, account_id: str) -> None:
        """
        Designate an account as the Security Hub delegated administrator
        for the organization.
        """
        try:
            self._org.register_delegated_administrator(
                AccountId=account_id,
                ServicePrincipal="securityhub.amazonaws.com",
            )
            logger.info("Registered %s as delegated admin for securityhub", account_id)
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            if code not in (
                "AccountAlreadyRegisteredException",
                "DelegatedAdministratorAlreadyRegisteredException",
            ):
                raise
            logger.info("Account %s already registered as delegated admin", account_id)

        try:
            self._sh.enable_organization_admin_account(AdminAccountId=account_id)
            logger.info("Enabled Security Hub org admin for account %s", account_id)
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            if code not in ("ResourceConflictException", "InvalidInputException"):
                raise
            logger.info("Security Hub org admin already set to %s", account_id)

    def enable_standard(self, account_id: str, standard_arn: str) -> str:
        """
        Subscribe the current account to a Security Hub compliance standard.
        Returns the StandardsSubscriptionArn.
        """
        # Normalize ARN for the current region
        region = self.session.region_name or "us-east-1"
        arn = standard_arn.replace("us-east-1", region)

        try:
            resp = self._sh.batch_enable_standards(
                StandardsSubscriptionRequests=[{"StandardsArn": arn}]
            )
            subscriptions = resp.get("StandardsSubscriptions", [])
            if subscriptions:
                sub_arn = subscriptions[0]["StandardsSubscriptionArn"]
                logger.info("Enabled standard %s for account %s → %s", arn, account_id, sub_arn)
                return sub_arn
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            if code == "InvalidInputException":
                logger.warning(
                    "Standard %s may already be enabled or ARN is invalid: %s", arn, exc
                )
            else:
                raise

        # Return existing subscription ARN if already enabled
        for page in self._sh.get_paginator("get_enabled_standards").paginate():
            for sub in page.get("StandardsSubscriptions", []):
                if sub["StandardsArn"] == arn:
                    return sub["StandardsSubscriptionArn"]

        return ""

    def get_findings(
        self,
        severity_labels: list[str],
        max_items: int = 100,
        workflow_statuses: list[str] | None = None,
    ) -> list[SecurityHubFinding]:
        """
        Fetch Security Hub findings filtered by severity labels and workflow status NEW.
        Returns up to max_items findings sorted by severity descending.
        """
        if workflow_statuses is None:
            workflow_statuses = ["NEW"]

        valid_severities = [s for s in severity_labels if s.upper() in SEVERITY_LABELS]
        if not valid_severities:
            raise ValueError(
                f"severity_labels must contain at least one of {SEVERITY_LABELS}"
            )

        filters: dict[str, Any] = {
            "SeverityLabel": [
                {"Value": s.upper(), "Comparison": "EQUALS"} for s in valid_severities
            ],
            "WorkflowStatus": [
                {"Value": ws, "Comparison": "EQUALS"} for ws in workflow_statuses
            ],
            "RecordState": [{"Value": "ACTIVE", "Comparison": "EQUALS"}],
        }

        findings: list[SecurityHubFinding] = []
        kwargs: dict[str, Any] = {"Filters": filters, "MaxResults": min(max_items, 100)}

        while len(findings) < max_items:
            resp = self._sh.get_findings(**kwargs)
            for raw in resp.get("Findings", []):
                findings.append(self._parse_finding(raw))
                if len(findings) >= max_items:
                    break
            next_token = resp.get("NextToken")
            if not next_token:
                break
            kwargs["NextToken"] = next_token

        severity_order = {s: i for i, s in enumerate(reversed(SEVERITY_LABELS))}
        findings.sort(key=lambda f: severity_order.get(f.severity, 0), reverse=True)
        logger.info("Fetched %d findings (severity=%s)", len(findings), valid_severities)
        return findings

    @staticmethod
    def _parse_finding(raw: dict) -> SecurityHubFinding:
        resources = raw.get("Resources", [{}])
        resource_arn = resources[0].get("Id", "") if resources else ""
        generator_id = raw.get("GeneratorId", "")
        # Extract control ID from generator ID format: "arn:.../control/CIS.1.1" or "CIS.1.1"
        control_id = generator_id.split("/")[-1] if "/" in generator_id else generator_id

        return SecurityHubFinding(
            finding_id=raw.get("Id", ""),
            title=raw.get("Title", ""),
            severity=raw.get("Severity", {}).get("Label", "INFORMATIONAL"),
            status=raw.get("Compliance", {}).get("Status", "UNKNOWN"),
            workflow_status=raw.get("Workflow", {}).get("Status", "NEW"),
            account_id=raw.get("AwsAccountId", ""),
            region=raw.get("Region", ""),
            resource_arn=resource_arn,
            control_id=control_id,
            updated_at=raw.get("UpdatedAt", ""),
        )

    def aggregate_by_control(
        self, findings: list[SecurityHubFinding]
    ) -> dict[str, ControlSummary]:
        """
        Group findings by control ID and return pass/fail/suppressed counts.
        Returns {control_id: ControlSummary}.
        """
        summaries: dict[str, ControlSummary] = {}

        for finding in findings:
            ctrl_id = finding.control_id or "UNKNOWN"
            if ctrl_id not in summaries:
                summaries[ctrl_id] = ControlSummary(
                    control_id=ctrl_id, title=finding.title
                )

            summary = summaries[ctrl_id]
            compliance = finding.status.upper()
            workflow = finding.workflow_status.upper()

            if workflow == "SUPPRESSED":
                summary.suppressed += 1
            elif compliance == "PASSED":
                summary.passed += 1
            else:
                summary.failed += 1

        logger.debug(
            "Aggregated %d findings into %d controls", len(findings), len(summaries)
        )
        return summaries

# _r 20260522153506-b61a1877
