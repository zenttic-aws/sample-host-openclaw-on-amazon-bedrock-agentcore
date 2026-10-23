"""Router Stack — API Gateway HTTP API for Telegram/Slack/Feishu/WhatsApp/Discord/LINE webhook ingestion.

Deploys the Router Lambda behind an API Gateway HTTP API with explicit
routes for each webhook path. Webhook secret validation (Telegram
secret_token header, Slack HMAC signature, Feishu X-Lark-Signature,
WhatsApp X-Hub-Signature-256, Discord Ed25519, LINE X-Line-Signature)
is enforced inside the Lambda. Also creates the DynamoDB identity table
for user resolution and cross-channel binding.
"""

from aws_cdk import (
    CfnOutput,
    Duration,
    RemovalPolicy,
    Stack,
    aws_apigatewayv2 as apigwv2,
    aws_apigatewayv2_integrations as apigwv2_integrations,
    aws_dynamodb as dynamodb,
    aws_iam as iam,
    aws_kms as kms,
    aws_lambda as _lambda,
    aws_logs as logs,
    aws_wafv2 as wafv2,
)
import cdk_nag
import json
from constructs import Construct

from scripts.model_selection import CONTEXT_KEY as MODEL_SELECTION_KEY, parse_user_selectable_models
from stacks import DeploymentNamer, apply_table_tags, retention_days


class RouterStack(Stack):
    def __init__(
        self,
        scope: Construct,
        construct_id: str,
        *,
        runtime_arn: str,
        runtime_endpoint_name: str,
        gateway_token_secret_name: str,
        telegram_token_secret_name: str,
        slack_token_secret_name: str,
        feishu_token_secret_name: str,
        webhook_secret_name: str,
        whatsapp_token_secret_name: str = "",
        discord_token_secret_name: str = "",
        line_token_secret_name: str = "",
        cmk_arn: str,
        user_files_bucket_name: str,
        user_files_bucket_arn: str,
        runtime_target: dict | None = None,
        **kwargs,
    ) -> None:
        super().__init__(scope, construct_id, **kwargs)

        namer = DeploymentNamer.from_scope(self)
        router_function_name = namer.name("openclaw-router")
        region = Stack.of(self).region
        account = Stack.of(self).account
        log_retention = self.node.try_get_context("cloudwatch_log_retention_days") or 30
        lambda_timeout = int(self.node.try_get_context("router_lambda_timeout_seconds") or "300")
        lambda_memory = int(self.node.try_get_context("router_lambda_memory_mb") or "256")
        # Reserved concurrency bounds the Router Lambda's share of the account
        # concurrency pool so the Cron and token-metrics functions cannot be
        # starved by a burst of webhook traffic. Set to 0 to disable (not
        # recommended) or raise via `router_reserved_concurrency` in cdk.json.
        router_reserved_concurrency = int(
            self.node.try_get_context("router_reserved_concurrency") or "100"
        )
        # Default stage throttle (POST event routes). Overridable via context.
        stage_rate_limit = int(
            self.node.try_get_context("router_stage_rate_limit") or "100"
        )
        stage_burst_limit = int(
            self.node.try_get_context("router_stage_burst_limit") or "50"
        )
        # Much lower limit for the unauthenticated GET surface (/health,
        # /webhook/whatsapp subscription verification) so one source cannot
        # drain the budget the signed POST webhooks need.
        get_route_rate_limit = int(
            self.node.try_get_context("router_unauth_get_rate_limit") or "10"
        )
        get_route_burst_limit = int(
            self.node.try_get_context("router_unauth_get_burst_limit") or "20"
        )
        # Optional WAFv2 WebACL with an IP-based rate rule in front of the
        # stage. Enabled by default; set `router_waf_enabled` to false to opt
        # out (for example on partitions where WAFv2 REGIONAL is unavailable).
        waf_flag = self.node.try_get_context("router_waf_enabled")
        router_waf_enabled = str(
            waf_flag if waf_flag is not None else "true"
        ).strip().lower() not in ("false", "0", "no", "off", "")
        waf_rate_limit = int(
            self.node.try_get_context("router_waf_rate_limit") or "2000"
        )
        registration_open = str(self.node.try_get_context("registration_open") or "false").lower()
        # Per-user `/model` switching: validated at synth so a bad map never deploys.
        user_selectable_models = parse_user_selectable_models(
            self.node.try_get_context(MODEL_SELECTION_KEY))
        default_model_id = self.node.try_get_context("default_model_id") or ""

        # --- DynamoDB Identity Table ---
        identity_cmk = kms.Key.from_key_arn(self, "IdentityTableCmk", cmk_arn)
        self.identity_table = dynamodb.Table(
            self,
            "IdentityTable",
            table_name=namer.name("openclaw-identity"),
            partition_key=dynamodb.Attribute(
                name="PK", type=dynamodb.AttributeType.STRING
            ),
            sort_key=dynamodb.Attribute(
                name="SK", type=dynamodb.AttributeType.STRING
            ),
            billing_mode=dynamodb.BillingMode.PAY_PER_REQUEST,
            removal_policy=RemovalPolicy.RETAIN,
            deletion_protection=True,
            time_to_live_attribute="ttl",
            point_in_time_recovery_specification=dynamodb.PointInTimeRecoverySpecification(
                point_in_time_recovery_enabled=True,
            ),
            encryption=dynamodb.TableEncryption.CUSTOMER_MANAGED,
            encryption_key=identity_cmk,
        )
        apply_table_tags(self.identity_table)

        # --- Log Group ---
        router_log_group = logs.LogGroup(
            self,
            "RouterLogGroup",
            log_group_name=namer.name("/openclaw/lambda/router"),
            retention=retention_days(log_retention),
            removal_policy=RemovalPolicy.DESTROY,
        )

        # --- Lambda Function ---
        self.router_fn = _lambda.Function(
            self,
            "RouterFn",
            function_name=router_function_name,
            runtime=_lambda.Runtime.PYTHON_3_13,
            handler="index.handler",
            code=_lambda.Code.from_asset("lambda/router"),
            layers=[_lambda.LayerVersion(
                self, "RuntimeRoutingLayer",
                code=_lambda.Code.from_asset("lambda/shared", exclude=["**/__pycache__/**", "**/*.pyc"]),
                compatible_runtimes=[_lambda.Runtime.PYTHON_3_13],
                description="Shared per-user AgentCore Runtime route resolution and admission",
            )],
            timeout=Duration.seconds(lambda_timeout),
            memory_size=lambda_memory,
            reserved_concurrent_executions=(
                router_reserved_concurrency if router_reserved_concurrency > 0 else None
            ),
            environment={
                "AGENTCORE_RUNTIME_ARN": runtime_arn,
                "AGENTCORE_QUALIFIER": runtime_endpoint_name,
                "IDENTITY_TABLE_NAME": self.identity_table.table_name,
                "TELEGRAM_TOKEN_SECRET_ID": telegram_token_secret_name,
                "SLACK_TOKEN_SECRET_ID": slack_token_secret_name,
                "FEISHU_TOKEN_SECRET_ID": feishu_token_secret_name,
                "WHATSAPP_TOKEN_SECRET_ID": whatsapp_token_secret_name,
                "DISCORD_TOKEN_SECRET_ID": discord_token_secret_name,
                "LINE_TOKEN_SECRET_ID": line_token_secret_name,
                "WEBHOOK_SECRET_ID": webhook_secret_name,
                "REGISTRATION_OPEN": registration_open,
                "USER_FILES_BUCKET": user_files_bucket_name,
                "LAMBDA_TIMEOUT_SECONDS": str(lambda_timeout),
                "RUNTIME_TARGET": json.dumps(runtime_target, separators=(",", ":")),
                "USER_SELECTABLE_MODELS": json.dumps(user_selectable_models, separators=(",", ":")),
                "DEFAULT_MODEL_ID": default_model_id,
            },
            log_group=router_log_group,
        )

        # --- API Gateway HTTP API ---
        # No default_integration — only explicit routes are exposed to reduce
        # attack surface. Unmatched paths return 404 from API Gateway itself.
        lambda_integration = apigwv2_integrations.HttpLambdaIntegration(
            "LambdaIntegration",
            handler=self.router_fn,
        )

        self.http_api = apigwv2.HttpApi(
            self,
            "RouterApi",
            api_name=namer.name("openclaw-router"),
            description="OpenClaw webhook ingestion API (explicit routes only)",
        )

        # Explicit routes — only these paths are reachable. The route keys of
        # unauthenticated GETs are collected so the stage can give them a
        # tighter per-route throttle than the signed POST event routes.
        self.http_api.add_routes(
            path="/webhook/telegram",
            methods=[apigwv2.HttpMethod.POST],
            integration=lambda_integration,
        )
        self.http_api.add_routes(
            path="/webhook/slack",
            methods=[apigwv2.HttpMethod.POST],
            integration=lambda_integration,
        )
        self.http_api.add_routes(
            path="/webhook/feishu",
            methods=[apigwv2.HttpMethod.POST],
            integration=lambda_integration,
        )
        # WhatsApp: GET is Meta's subscription verification, POST carries events.
        # Both return 404 from the Lambda until the channel secret is configured.
        self.http_api.add_routes(
            path="/webhook/whatsapp",
            methods=[apigwv2.HttpMethod.GET, apigwv2.HttpMethod.POST],
            integration=lambda_integration,
        )
        self.http_api.add_routes(
            path="/webhook/discord",
            methods=[apigwv2.HttpMethod.POST],
            integration=lambda_integration,
        )
        # LINE Messaging API webhook. Returns 404 from the Lambda until the
        # channel secret is configured.
        self.http_api.add_routes(
            path="/webhook/line",
            methods=[apigwv2.HttpMethod.POST],
            integration=lambda_integration,
        )
        self.http_api.add_routes(
            path="/health",
            methods=[apigwv2.HttpMethod.GET],
            integration=lambda_integration,
        )

        # Route keys that any internet client can reach without a signing
        # key — /health is answered before validation and /webhook/whatsapp
        # GET is Meta's subscription verification. They get a much lower
        # per-route limit than the signed POST routes so one unauthenticated
        # source cannot consume the global budget.
        unauth_get_route_keys = [
            "GET /health",
            "GET /webhook/whatsapp",
        ]

        # --- Access Logging ---
        access_log_group = logs.LogGroup(
            self,
            "ApiAccessLogGroup",
            log_group_name=namer.name("/openclaw/api-access"),
            retention=retention_days(log_retention),
            removal_policy=RemovalPolicy.RETAIN,
        )

        # Throttling + access logging — configured on the default stage
        default_stage = self.http_api.default_stage
        if default_stage:
            cfn_stage = default_stage.node.default_child
            cfn_stage.default_route_settings = apigwv2.CfnStage.RouteSettingsProperty(
                throttling_burst_limit=stage_burst_limit,
                throttling_rate_limit=stage_rate_limit,
                detailed_metrics_enabled=True,
            )
            # Per-route overrides: tighter cap on unauthenticated GET routes
            # so they cannot drain the stage-wide bucket the signed POST event
            # routes need. API Gateway v2 uses the route key ("METHOD /path")
            # as the map key.
            cfn_stage.route_settings = {
                route_key: apigwv2.CfnStage.RouteSettingsProperty(
                    throttling_burst_limit=get_route_burst_limit,
                    throttling_rate_limit=get_route_rate_limit,
                    detailed_metrics_enabled=True,
                )
                for route_key in unauth_get_route_keys
            }
            cfn_stage.access_log_settings = apigwv2.CfnStage.AccessLogSettingsProperty(
                destination_arn=access_log_group.log_group_arn,
                format='{"requestId":"$context.requestId","ip":"$context.identity.sourceIp","method":"$context.httpMethod","path":"$context.path","status":"$context.status","responseLength":"$context.responseLength","latency":"$context.responseLatency","time":"$context.requestTime"}',
            )

            # --- Optional WAFv2 WebACL with IP-based rate limit ---
            # One rate-based rule keyed on the source IP, so a single
            # unauthenticated source cannot consume the whole stage budget.
            # Associated to the API Gateway v2 stage (REGIONAL scope).
            if router_waf_enabled:
                web_acl = wafv2.CfnWebACL(
                    self,
                    "RouterWebAcl",
                    name=namer.name("openclaw-router-waf"),
                    scope="REGIONAL",
                    default_action=wafv2.CfnWebACL.DefaultActionProperty(
                        allow=wafv2.CfnWebACL.AllowActionProperty()
                    ),
                    visibility_config=wafv2.CfnWebACL.VisibilityConfigProperty(
                        cloud_watch_metrics_enabled=True,
                        metric_name=namer.name("openclaw-router-waf"),
                        sampled_requests_enabled=True,
                    ),
                    rules=[
                        wafv2.CfnWebACL.RuleProperty(
                            name="RateLimitPerSourceIp",
                            priority=0,
                            action=wafv2.CfnWebACL.RuleActionProperty(
                                block=wafv2.CfnWebACL.BlockActionProperty()
                            ),
                            statement=wafv2.CfnWebACL.StatementProperty(
                                rate_based_statement=wafv2.CfnWebACL.RateBasedStatementProperty(
                                    limit=waf_rate_limit,
                                    aggregate_key_type="IP",
                                )
                            ),
                            visibility_config=wafv2.CfnWebACL.VisibilityConfigProperty(
                                cloud_watch_metrics_enabled=True,
                                metric_name=namer.name(
                                    "openclaw-router-waf-ratelimit"
                                ),
                                sampled_requests_enabled=True,
                            ),
                        ),
                    ],
                )
                stage_arn = (
                    f"arn:{Stack.of(self).partition}:apigateway:{region}::"
                    f"/apis/{self.http_api.api_id}/stages/{default_stage.stage_name}"
                )
                waf_association = wafv2.CfnWebACLAssociation(
                    self,
                    "RouterWebAclAssoc",
                    resource_arn=stage_arn,
                    web_acl_arn=web_acl.attr_arn,
                )
                # Create order: the WebACL must exist before the stage is
                # associated. CfnStage is the L1 child of the default stage.
                waf_association.add_dependency(cfn_stage)
                waf_association.add_dependency(web_acl)

        # --- IAM Permissions ---

        # AgentCore Runtime invocation — scoped to specific runtime and its endpoints
        # IAM evaluates against runtime/{id}/runtime-endpoint/{endpoint-id}
        if runtime_arn:
            self.router_fn.add_to_role_policy(
                iam.PolicyStatement(
                    actions=["bedrock-agentcore:InvokeAgentRuntime"],
                    resources=[runtime_arn, f"{runtime_arn}/*"],
                )
            )

        # DynamoDB read/write
        self.identity_table.grant_read_write_data(self.router_fn)

        # Lambda self-invoke (for async dispatch)
        # Use constructed ARN to avoid circular dependency with Function URL
        self.router_fn.add_to_role_policy(
            iam.PolicyStatement(
                actions=["lambda:InvokeFunction"],
                resources=[
                    f"arn:aws:lambda:{region}:{account}:function:{router_function_name}",
                ],
            )
        )

        # Secrets Manager (channel tokens)
        self.router_fn.add_to_role_policy(
            iam.PolicyStatement(
                actions=[
                    "secretsmanager:GetSecretValue",
                    "secretsmanager:DescribeSecret",
                ],
                resources=[
                    f"arn:aws:secretsmanager:{region}:{account}:secret:openclaw/*",
                ],
            )
        )

        # KMS decrypt for secrets
        self.router_fn.add_to_role_policy(
            iam.PolicyStatement(
                actions=["kms:Decrypt"],
                resources=[cmk_arn],
            )
        )

        # S3 PutObject for image uploads (scoped to _uploads/ prefix)
        self.router_fn.add_to_role_policy(
            iam.PolicyStatement(
                actions=["s3:PutObject"],
                resources=[f"{user_files_bucket_arn}/*/_uploads/*"],
            )
        )

        # KMS GenerateDataKey for S3 bucket encryption (bucket uses KMS CMK)
        self.router_fn.add_to_role_policy(
            iam.PolicyStatement(
                actions=["kms:GenerateDataKey"],
                resources=[cmk_arn],
            )
        )

        # --- Outputs ---
        CfnOutput(
            self,
            "ApiUrl",
            value=self.http_api.url or "",
            description="Router API Gateway URL for webhook registration",
        )
        CfnOutput(
            self,
            "IdentityTableName",
            value=self.identity_table.table_name,
        )

        # --- cdk-nag suppressions ---
        cdk_nag.NagSuppressions.add_resource_suppressions(
            self.router_fn,
            [
                cdk_nag.NagPackSuppression(
                    id="AwsSolutions-IAM4",
                    reason="Lambda basic execution role is AWS-recommended for CloudWatch Logs.",
                    applies_to=[
                        "Policy::arn:<AWS::Partition>:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole",
                    ],
                ),
                cdk_nag.NagPackSuppression(
                    id="AwsSolutions-IAM5",
                    reason="AgentCore InvokeAgentRuntime IAM resource must include "
                    "runtime-endpoint sub-resource path (runtime/{id}/*). "
                    "Secrets Manager scoped to openclaw/* prefix. DynamoDB "
                    "grant_read_write_data adds index wildcards and KMS wildcards "
                    "for CMK-encrypted table. S3 PutObject scoped to */_uploads/* "
                    "prefix for image uploads.",
                    applies_to=[
                        *([f"Resource::{runtime_arn}/*"] if runtime_arn else []),
                        f"Resource::arn:aws:secretsmanager:{region}:{account}:secret:openclaw/*",
                        f"Resource::{self.identity_table.table_arn}/index/*",
                        "Resource::<UserFilesBucketCFDFD8C0.Arn>/*/_uploads/*",
                        "Action::kms:GenerateDataKey*",
                        "Action::kms:ReEncrypt*",
                    ],
                ),
                cdk_nag.NagPackSuppression(
                    id="AwsSolutions-L1",
                    reason="Python 3.13 is the latest stable runtime supported in all regions.",
                ),
            ],
            apply_to_children=True,
        )
        cdk_nag.NagSuppressions.add_resource_suppressions(
            self.http_api,
            [
                cdk_nag.NagPackSuppression(
                    id="AwsSolutions-APIG4",
                    reason="External webhooks (Telegram, Slack, Feishu, WhatsApp, Discord, LINE) cannot use "
                    "IAM/JWT auth. Webhook signature validation is enforced in the Lambda "
                    "handler: Telegram X-Telegram-Bot-Api-Secret-Token header, Slack "
                    "X-Slack-Signature HMAC, Feishu X-Lark-Signature and WhatsApp "
                    "X-Hub-Signature-256 HMAC (plus a constant-time verify-token check on "
                    "its GET subscription route), Discord X-Signature-Ed25519 and LINE "
                    "X-Line-Signature HMAC. API Gateway stage throttling plus "
                    "tighter per-route throttles on the unauthenticated GET "
                    "routes (/health, /webhook/whatsapp subscription "
                    "verification), a WAFv2 rate-based rule keyed on source "
                    "IP, and a reserved concurrency cap on the Router Lambda "
                    "together provide rate limiting. Only explicit routes "
                    "are exposed.",
                ),
                cdk_nag.NagPackSuppression(
                    id="AwsSolutions-APIG1",
                    reason="Access logging IS configured via L1 escape hatch "
                    "(CfnStage.access_log_settings) to /openclaw/api-access log group. "
                    "cdk-nag cannot detect L1-level access log configuration.",
                ),
            ],
            apply_to_children=True,
        )
