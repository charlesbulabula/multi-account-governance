"""
GovernanceStack — AWS CDK stack for org-wide governance:
  - SCP: deny-leave-organization policy via CfnPolicy
  - AWS Config org-wide aggregator
  - CloudTrail organization trail to S3 + CloudWatch Logs
  - EventBridge rule for Config NON_COMPLIANT → SNS
  - Security Hub CfnHub with auto-enable
"""

import json

from aws_cdk import (
    Duration,
    RemovalPolicy,
    Stack,
    aws_cloudtrail as cloudtrail,
    aws_config as config,
    aws_events as events,
    aws_events_targets as targets,
    aws_iam as iam,
    aws_logs as logs,
    aws_organizations as organizations,
    aws_s3 as s3,
    aws_securityhub as securityhub,
    aws_sns as sns,
    aws_sns_subscriptions as subs,
)
from constructs import Construct

DENY_LEAVE_ORG_POLICY = {
    "Version": "2012-10-17",
    "Statement": [
        {
            "Sid": "DenyLeaveOrganization",
            "Effect": "Deny",
            "Action": ["organizations:LeaveOrganization"],
            "Resource": "*",
        }
    ],
}


class GovernanceStack(Stack):
    """
    Deploys org-wide governance infrastructure: SCPs, Config aggregation,
    CloudTrail, EventBridge compliance alerting, and Security Hub.
    """

    def __init__(
        self,
        scope: Construct,
        construct_id: str,
        *,
        org_id: str,
        management_account_id: str,
        member_account_ids: list[str],
        compliance_email: str,
        **kwargs,
    ) -> None:
        super().__init__(scope, construct_id, **kwargs)

        self.org_id = org_id
        self.management_account_id = management_account_id

        # 1. SCP: deny leave-organization
        self.deny_leave_scp = self._create_deny_leave_scp()

        # 2. CloudTrail org trail
        trail_bucket, self.org_trail = self._create_org_trail()

        # 3. Config org-wide aggregator
        self.config_aggregator = self._create_config_aggregator()

        # 4. Compliance SNS topic + EventBridge rule
        self.compliance_topic = self._create_compliance_alerting(compliance_email)

        # 5. Security Hub with auto-enable
        self.security_hub = self._create_security_hub()

    # -------------------------------------------------------------------------
    # SCP
    # -------------------------------------------------------------------------

    def _create_deny_leave_scp(self) -> organizations.CfnPolicy:
        return organizations.CfnPolicy(
            self,
            "DenyLeaveOrgSCP",
            name="deny-leave-organization",
            description="Prevents member accounts from leaving the organization",
            type="SERVICE_CONTROL_POLICY",
            content=json.dumps(DENY_LEAVE_ORG_POLICY, separators=(",", ":")),
        )

    # -------------------------------------------------------------------------
    # CloudTrail
    # -------------------------------------------------------------------------

    def _create_org_trail(self) -> tuple[s3.Bucket, cloudtrail.CfnTrail]:
        bucket = s3.Bucket(
            self,
            "CloudTrailBucket",
            bucket_name=f"org-cloudtrail-{self.management_account_id}",
            encryption=s3.BucketEncryption.S3_MANAGED,
            block_public_access=s3.BlockPublicAccess.BLOCK_ALL,
            versioned=True,
            lifecycle_rules=[
                s3.LifecycleRule(
                    id="archive-and-expire",
                    transitions=[
                        s3.Transition(
                            storage_class=s3.StorageClass.INTELLIGENT_TIERING,
                            transition_after=Duration.days(90),
                        )
                    ],
                    expiration=Duration.days(2555),  # 7 years
                )
            ],
            removal_policy=RemovalPolicy.RETAIN,
        )

        # Allow CloudTrail to write to the bucket
        bucket.add_to_resource_policy(
            iam.PolicyStatement(
                sid="AWSCloudTrailAclCheck",
                principals=[iam.ServicePrincipal("cloudtrail.amazonaws.com")],
                actions=["s3:GetBucketAcl"],
                resources=[bucket.bucket_arn],
            )
        )
        bucket.add_to_resource_policy(
            iam.PolicyStatement(
                sid="AWSCloudTrailWrite",
                principals=[iam.ServicePrincipal("cloudtrail.amazonaws.com")],
                actions=["s3:PutObject"],
                resources=[f"{bucket.bucket_arn}/AWSLogs/{self.org_id}/*"],
                conditions={"StringEquals": {"s3:x-amz-acl": "bucket-owner-full-control"}},
            )
        )

        log_group = logs.LogGroup(
            self,
            "CloudTrailLogGroup",
            log_group_name="/aws/cloudtrail/org-trail",
            retention=logs.RetentionDays.ONE_YEAR,
            removal_policy=RemovalPolicy.RETAIN,
        )

        trail_role = iam.Role(
            self,
            "CloudTrailCWLogsRole",
            assumed_by=iam.ServicePrincipal("cloudtrail.amazonaws.com"),
            inline_policies={
                "AllowCWLogs": iam.PolicyDocument(
                    statements=[
                        iam.PolicyStatement(
                            actions=["logs:CreateLogStream", "logs:PutLogEvents"],
                            resources=[f"{log_group.log_group_arn}:*"],
                        )
                    ]
                )
            },
        )

        trail = cloudtrail.CfnTrail(
            self,
            "OrgTrail",
            trail_name="org-wide-cloudtrail",
            s3_bucket_name=bucket.bucket_name,
            is_logging=True,
            is_multi_region_trail=True,
            is_organization_trail=True,
            enable_log_file_validation=True,
            include_global_service_events=True,
            cloud_watch_logs_log_group_arn=log_group.log_group_arn,
            cloud_watch_logs_role_arn=trail_role.role_arn,
        )
        trail.add_dependency(bucket.node.default_child)  # type: ignore[arg-type]

        return bucket, trail

    # -------------------------------------------------------------------------
    # Config Aggregator
    # -------------------------------------------------------------------------

    def _create_config_aggregator(self) -> config.CfnConfigurationAggregator:
        aggregator_role = iam.Role(
            self,
            "ConfigAggregatorRole",
            assumed_by=iam.ServicePrincipal("config.amazonaws.com"),
            managed_policies=[
                iam.ManagedPolicy.from_aws_managed_policy_name(
                    "service-role/AWSConfigRoleForOrganizations"
                )
            ],
        )

        return config.CfnConfigurationAggregator(
            self,
            "OrgConfigAggregator",
            configuration_aggregator_name="org-config-aggregator",
            organization_aggregation_source=config.CfnConfigurationAggregator.OrganizationAggregationSourceProperty(
                role_arn=aggregator_role.role_arn,
                all_aws_regions=True,
            ),
        )

    # -------------------------------------------------------------------------
    # Compliance Alerting
    # -------------------------------------------------------------------------

    def _create_compliance_alerting(self, compliance_email: str) -> sns.Topic:
        topic = sns.Topic(
            self,
            "ComplianceAlertsTopic",
            topic_name="governance-compliance-alerts",
            display_name="Governance Compliance Alerts",
        )
        topic.add_subscription(subs.EmailSubscription(compliance_email))

        # EventBridge rule: Config NON_COMPLIANT findings
        noncompliant_rule = events.Rule(
            self,
            "ConfigNonCompliantRule",
            rule_name="governance-config-noncompliant",
            description="Alert on Config rule evaluations changing to NON_COMPLIANT",
            event_pattern=events.EventPattern(
                source=["aws.config"],
                detail_type=["Config Rules Compliance Change"],
                detail={"newEvaluationResult": {"complianceType": ["NON_COMPLIANT"]}},
            ),
        )
        noncompliant_rule.add_target(
            targets.SnsTopic(
                topic,
                message=events.RuleTargetInput.from_event_path("$.detail"),
            )
        )

        # EventBridge rule: CloudTrail tampering
        events.Rule(
            self,
            "CloudTrailTamperRule",
            rule_name="governance-cloudtrail-tamper",
            description="Alert on CloudTrail stop/delete/update events",
            event_pattern=events.EventPattern(
                source=["aws.cloudtrail"],
                detail_type=["AWS API Call via CloudTrail"],
                detail={
                    "eventSource": ["cloudtrail.amazonaws.com"],
                    "eventName": ["StopLogging", "DeleteTrail", "UpdateTrail"],
                },
            ),
        ).add_target(targets.SnsTopic(topic))

        return topic

    # -------------------------------------------------------------------------
    # Security Hub
    # -------------------------------------------------------------------------

    def _create_security_hub(self) -> securityhub.CfnHub:
        return securityhub.CfnHub(
            self,
            "SecurityHub",
            auto_enable_controls=True,
            control_finding_generator="SECURITY_CONTROL",
            tags={
                "ManagedBy": "governance-stack",
                "OrgId": self.org_id,
            },
        )

# _r 20260610110309-5fe9757e
