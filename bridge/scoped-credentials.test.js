/**
 * Tests for scoped-credentials.js — STS session-scoped S3 credentials.
 *
 * Covers: buildSessionPolicy, createScopedCredentials, writeCredentialFiles,
 *         buildOpenClawEnv, credential refresh lifecycle.
 * Run: cd bridge && node --test scoped-credentials.test.js
 */
const { describe, it, beforeEach, afterEach, mock } = require("node:test");
const assert = require("node:assert/strict");
const fs = require("fs");
const path = require("path");
const os = require("os");

// --- buildSessionPolicy ---

describe("buildSessionPolicy", () => {
  let buildSessionPolicy;

  beforeEach(() => {
    ({ buildSessionPolicy } = require("./scoped-credentials"));
  });

  it("returns valid JSON policy with S3 scoped to namespace", () => {
    const policy = buildSessionPolicy({
      bucket: "openclaw-user-files-123-us-west-2",
      namespace: "telegram_12345",
      cmkArn: "arn:aws:kms:us-west-2:123:key/abc-123",
    });

    const parsed = JSON.parse(policy);
    assert.equal(parsed.Version, "2012-10-17");
    assert.ok(Array.isArray(parsed.Statement));
    // Minimum statements: S3 object + S3 list + secrets CRUD + secrets list + KMS.
    // DynamoDB / Scheduler / PassRole are added only when the matching ARN is
    // provided. All resources must be scoped — wildcards are a cross-tenant
    // isolation violation and are asserted absent below.
    assert.ok(parsed.Statement.length >= 5,
      `should have at least 5 statements (S3x2, secrets CRUD, secrets list, KMS), got ${parsed.Statement.length}`);
  });

  it("policy stays within the 2048-byte STS packed-policy limit for realistic inputs", () => {
    const policy = buildSessionPolicy({
      bucket: "openclaw-user-files-123456789012-us-west-2-production",
      namespace: "discord_123456789012345678",
      actorId: "discord:123456789012345678",
      internalUserId: "user_abc123def4567890",
      cmkArn: "arn:aws:kms:us-west-2:123456789012:key/abcdef12-3456-7890-abcd-ef1234567890",
      eventbridgeRoleArn: "arn:aws:iam::123456789012:role/openclaw-cron-scheduler-role-us-west-2-production",
      identityTableArn: "arn:aws:dynamodb:us-west-2:123456789012:table/openclaw-identity-production",
      scheduleGroupArn: "arn:aws:scheduler:us-west-2:123456789012:schedule-group/openclaw-cron-production",
      region: "us-west-2",
      account: "123456789012",
    });
    assert.ok(policy.length <= 2048,
      `policy must be <= 2048 bytes (STS packed limit), got ${policy.length}`);
  });

  it("policy stays within the 2048-byte limit for a 46-char namespace with suffixed resource names", () => {
    // 46 chars is the longest namespace the eventbridge-cron skill accepts;
    // Feishu open_id namespaces ("feishu_ou_" + 32 hex) are 42.
    const ns = "feishu_ou_" + "0123456789abcdef".repeat(2) + "abcd";
    assert.equal(ns.length, 46);
    const policy = buildSessionPolicy({
      bucket: "openclaw-user-files-123456789012-ap-southeast-2-production",
      namespace: ns,
      internalUserId: "user_0123456789abcdef",
      cmkArn: "arn:aws:kms:ap-southeast-2:123456789012:key/abcdef12-3456-7890-abcd-ef1234567890",
      eventbridgeRoleArn: "arn:aws:iam::123456789012:role/openclaw-cron-scheduler-role-ap-southeast-2-production",
      identityTableArn: "arn:aws:dynamodb:ap-southeast-2:123456789012:table/openclaw-identity-production",
      scheduleGroupArn: "arn:aws:scheduler:ap-southeast-2:123456789012:schedule-group/openclaw-cron-production",
      region: "ap-southeast-2",
      account: "123456789012",
    });
    assert.ok(policy.length <= 2048,
      `policy must be <= 2048 bytes (STS packed limit), got ${policy.length}`);
  });

  it("S3 object actions scoped to namespace/* only", () => {
    const policy = buildSessionPolicy({
      bucket: "my-bucket",
      namespace: "slack_U0ABC",
      cmkArn: "arn:aws:kms:us-west-2:123:key/abc-123",
    });

    const parsed = JSON.parse(policy);
    const objectStmt = parsed.Statement.find(
      (s) => s.Action && (Array.isArray(s.Action) ? s.Action.includes("s3:GetObject") : s.Action === "s3:GetObject*")
    );
    assert.ok(objectStmt, "should have S3 object statement");

    // Resource should include namespace-scoped object ARN
    const resources = Array.isArray(objectStmt.Resource)
      ? objectStmt.Resource
      : [objectStmt.Resource];
    assert.ok(
      resources.some((r) => r.includes("slack_U0ABC")),
      `at least one resource should contain namespace, got: ${resources}`,
    );
    // Must NOT grant access to the whole bucket with /*
    assert.ok(
      !resources.some((r) => r.endsWith("/*") && !r.includes("slack_U0ABC")),
      "should not grant bucket-wide access",
    );
  });

  it("ListBucket included in S3 statement with namespace prefix Condition", () => {
    const policy = buildSessionPolicy({
      bucket: "my-bucket",
      namespace: "telegram_99999",
      cmkArn: "arn:aws:kms:us-west-2:123:key/abc-123",
    });

    const parsed = JSON.parse(policy);
    const listStmt = parsed.Statement.find(
      (s) => s.Action && (Array.isArray(s.Action) ? s.Action.includes("s3:ListBucket") : s.Action === "s3:ListBucket")
    );
    assert.ok(listStmt, "should have ListBucket statement");
    assert.ok(listStmt.Condition, "ListBucket should have a Condition block");
    const prefixes = listStmt.Condition.StringLike && listStmt.Condition.StringLike["s3:prefix"];
    assert.ok(Array.isArray(prefixes), "s3:prefix condition should be an array");
    assert.ok(
      prefixes.includes("telegram_99999/*"),
      `s3:prefix should include namespace/*, got: ${JSON.stringify(prefixes)}`,
    );
    // Must not allow listing other namespaces or the bucket root.
    assert.ok(
      !prefixes.some((p) => p === "*" || p === ""),
      `s3:prefix must not allow wildcard/root, got: ${JSON.stringify(prefixes)}`,
    );
  });

  it("KMS statement is scoped to the deployment CMK and pinned by kms:ViaService", () => {
    const policy = buildSessionPolicy({
      bucket: "my-bucket",
      namespace: "telegram_12345",
      cmkArn: "arn:aws:kms:us-west-2:123:key/abc-123",
      region: "us-west-2",
    });

    const parsed = JSON.parse(policy);
    const kmsStmt = parsed.Statement.find(
      (s) =>
        s.Action &&
        (Array.isArray(s.Action)
          ? s.Action.some((a) => a.startsWith("kms:"))
          : s.Action.startsWith("kms:")),
    );
    assert.ok(kmsStmt, "should have KMS actions");
    assert.equal(kmsStmt.Resource, "arn:aws:kms:us-west-2:123:key/abc-123",
      "KMS resource must be the specific CMK, not a wildcard");
    assert.ok(kmsStmt.Condition, "KMS statement must carry a kms:ViaService condition");
    const viaService = kmsStmt.Condition.StringLike && kmsStmt.Condition.StringLike["kms:ViaService"];
    assert.ok(viaService, "kms:ViaService condition must be present");
  });

  it("KMS falls back to wildcard resource only when cmkArn is unknown but still carries ViaService", () => {
    const policy = buildSessionPolicy({
      bucket: "my-bucket",
      namespace: "telegram_12345",
      region: "us-west-2",
    });

    const parsed = JSON.parse(policy);
    const kmsStmt = parsed.Statement.find(
      (s) =>
        s.Action &&
        (Array.isArray(s.Action)
          ? s.Action.some((a) => a.startsWith("kms:"))
          : s.Action.startsWith("kms:")),
    );
    assert.ok(kmsStmt, "KMS actions should be present even without cmkArn");
    assert.ok(kmsStmt.Condition, "KMS without a CMK must still carry ViaService");
  });

  it("iam:PassRole is scoped to the scheduler role and requires PassedToService=scheduler", () => {
    const roleArn = "arn:aws:iam::123:role/openclaw-cron-scheduler-role";
    const policy = buildSessionPolicy({
      bucket: "my-bucket",
      namespace: "telegram_12345",
      cmkArn: "arn:aws:kms:us-west-2:123:key/abc-123",
      eventbridgeRoleArn: roleArn,
    });

    const parsed = JSON.parse(policy);
    const passRoleStmt = parsed.Statement.find(
      (s) => Array.isArray(s.Action)
        ? s.Action.includes("iam:PassRole")
        : s.Action === "iam:PassRole",
    );
    assert.ok(passRoleStmt, "should have PassRole action");
    assert.equal(passRoleStmt.Resource, roleArn,
      "PassRole resource must be the specific scheduler role, not a wildcard");
    assert.deepEqual(
      passRoleStmt.Condition,
      { StringEquals: { "iam:PassedToService": "scheduler.amazonaws.com" } },
      "PassRole must require iam:PassedToService=scheduler.amazonaws.com",
    );
  });

  it("iam:PassRole statement is omitted when eventbridgeRoleArn is unknown", () => {
    const policy = buildSessionPolicy({
      bucket: "my-bucket",
      namespace: "telegram_12345",
      cmkArn: "arn:aws:kms:us-west-2:123:key/abc-123",
    });

    const parsed = JSON.parse(policy);
    const passRoleStmt = parsed.Statement.find(
      (s) => Array.isArray(s.Action)
        ? s.Action.includes("iam:PassRole")
        : s.Action === "iam:PassRole",
    );
    assert.equal(passRoleStmt, undefined,
      "PassRole must not be granted when the target role is unknown (fail closed, not wildcard)");
  });

  it("rejects namespace with path traversal", () => {
    assert.throws(
      () =>
        buildSessionPolicy({
          bucket: "my-bucket",
          namespace: "../other-user",
          cmkArn: "arn:aws:kms:us-west-2:123:key/abc-123",
        }),
      /invalid namespace/i,
    );
  });

  it("rejects empty namespace", () => {
    assert.throws(
      () =>
        buildSessionPolicy({
          bucket: "my-bucket",
          namespace: "",
          cmkArn: "arn:aws:kms:us-west-2:123:key/abc-123",
        }),
      /invalid namespace/i,
    );
  });

  it("DynamoDB actions are scoped to the identity table and its indexes", () => {
    const tableArn = "arn:aws:dynamodb:us-west-2:123456789012:table/openclaw-identity";
    const policy = buildSessionPolicy({
      bucket: "my-bucket",
      namespace: "telegram_12345",
      actorId: "telegram:12345",
      internalUserId: "user_abc123",
      identityTableArn: tableArn,
    });

    const parsed = JSON.parse(policy);
    const dynamoStmt = parsed.Statement.find((s) => Array.isArray(s.Action) && s.Action.includes("dynamodb:GetItem"));
    assert.ok(dynamoStmt, "should have DynamoDB actions");
    const resources = Array.isArray(dynamoStmt.Resource) ? dynamoStmt.Resource : [dynamoStmt.Resource];
    assert.ok(resources.includes(tableArn), "should include the table ARN");
    assert.ok(!resources.includes(`${tableArn}/index/*`), "no skill queries a GSI, so index ARNs are not granted");
    assert.ok(!resources.includes("*"), "must not grant DynamoDB access to all resources");
  });

  it("DynamoDB statement is omitted when identityTableArn is unknown", () => {
    const policy = buildSessionPolicy({
      bucket: "my-bucket",
      namespace: "telegram_12345",
    });

    const parsed = JSON.parse(policy);
    const dynamoStmt = parsed.Statement.find((s) => Array.isArray(s.Action) && s.Action.includes("dynamodb:GetItem"));
    assert.equal(dynamoStmt, undefined,
      "DynamoDB must not be granted when the table ARN is unknown (fail closed, not wildcard)");
  });

  it("DynamoDB statement carries a LeadingKeys condition pinned to the caller's own partition keys", () => {
    const policy = buildSessionPolicy({
      bucket: "my-bucket",
      namespace: "telegram_12345",
      actorId: "telegram:12345",
      internalUserId: "user_abc123",
      identityTableArn: "arn:aws:dynamodb:us-west-2:123456789012:table/openclaw-identity",
    });

    const parsed = JSON.parse(policy);
    const dynamoStmt = parsed.Statement.find((s) => Array.isArray(s.Action) && s.Action.includes("dynamodb:GetItem"));
    assert.ok(dynamoStmt.Condition, "DynamoDB must carry a LeadingKeys condition");
    const leadingKeys = dynamoStmt.Condition["ForAllValues:StringEquals"]["dynamodb:LeadingKeys"];
    assert.deepEqual(
      new Set(leadingKeys),
      new Set(["USER#user_abc123", "CHANNEL#telegram:12345"]),
      "LeadingKeys must only include this caller's USER#/CHANNEL# keys",
    );
  });

  it("Scheduler CRUD is scoped to the caller's schedule-name prefix within the deployment group", () => {
    const policy = buildSessionPolicy({
      bucket: "my-bucket",
      namespace: "telegram_12345",
      scheduleGroupArn: "arn:aws:scheduler:us-west-2:123456789012:schedule-group/openclaw-cron",
    });

    const parsed = JSON.parse(policy);
    const ebStmt = parsed.Statement.find(
      (s) => Array.isArray(s.Action) && s.Action.includes("scheduler:CreateSchedule"),
    );
    assert.ok(ebStmt, "should have scheduler CRUD actions");
    assert.ok(!ebStmt.Action.includes("scheduler:*"),
      "must not grant scheduler:* — only the four CRUD actions this agent needs");
    assert.equal(
      ebStmt.Resource,
      "arn:aws:scheduler:us-west-2:123456789012:schedule/openclaw-cron/openclaw-telegram_12345-*",
      "scheduler resource must be restricted to the per-namespace schedule-name prefix",
    );
    // ListSchedules is intentionally omitted: enumeration happens via the
    // DynamoDB CRON# records which carry a per-user LeadingKeys condition.
    const listStmt = parsed.Statement.find(
      (s) => s.Action === "scheduler:ListSchedules"
        || (Array.isArray(s.Action) && s.Action.includes("scheduler:ListSchedules")),
    );
    assert.equal(listStmt, undefined,
      "ListSchedules must not be granted — it leaks other tenants' schedule names in the shared group");
  });

  it("Scheduler statement is omitted when scheduleGroupArn is unknown", () => {
    const policy = buildSessionPolicy({
      bucket: "my-bucket",
      namespace: "telegram_12345",
    });

    const parsed = JSON.parse(policy);
    const ebStmt = parsed.Statement.find(
      (s) => Array.isArray(s.Action) && s.Action.some((a) => a.startsWith("scheduler:")),
    );
    assert.equal(ebStmt, undefined,
      "Scheduler must not be granted when the schedule group ARN is unknown (fail closed, not wildcard)");
  });

  it("never emits a wildcard resource on any privileged service", () => {
    const policy = buildSessionPolicy({
      bucket: "my-bucket",
      namespace: "telegram_12345",
      actorId: "telegram:12345",
      internalUserId: "user_abc123",
      cmkArn: "arn:aws:kms:us-west-2:123:key/abc-123",
      eventbridgeRoleArn: "arn:aws:iam::123:role/openclaw-cron-scheduler-role",
      identityTableArn: "arn:aws:dynamodb:us-west-2:123456789012:table/openclaw-identity",
      scheduleGroupArn: "arn:aws:scheduler:us-west-2:123456789012:schedule-group/openclaw-cron",
      region: "us-west-2",
      account: "123456789012",
    });
    const parsed = JSON.parse(policy);

    // The only places Resource:"*" is acceptable are services that do not
    // support resource-level permissions (secretsmanager:ListSecrets) — and
    // even there the statement must grant only that single action.
    for (const stmt of parsed.Statement) {
      const resources = Array.isArray(stmt.Resource) ? stmt.Resource : [stmt.Resource];
      if (!resources.includes("*")) continue;
      const actions = Array.isArray(stmt.Action) ? stmt.Action : [stmt.Action];
      for (const action of actions) {
        assert.equal(action, "secretsmanager:ListSecrets",
          `wildcard Resource is only allowed for secretsmanager:ListSecrets, found action=${action}`);
      }
    }
  });
});

// --- createScopedCredentials ---

describe("createScopedCredentials", () => {
  let createScopedCredentials, _mockStsClient;

  const MOCK_CREDS = {
    AccessKeyId: "AKIAIOSFODNN7EXAMPLE",
    SecretAccessKey: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
    SessionToken: "FwoGZXIvYXdzEBYaDH...",
    Expiration: new Date(Date.now() + 3600000),
  };

  beforeEach(() => {
    // Re-require to get fresh module with mock injection
    delete require.cache[require.resolve("./scoped-credentials")];

    // Mock STS client
    _mockStsClient = {
      send: mock.fn(async () => ({
        Credentials: { ...MOCK_CREDS },
      })),
    };

    // Set required env vars
    process.env.S3_USER_FILES_BUCKET = "test-bucket";
    process.env.AWS_REGION = "us-west-2";
    process.env.EXECUTION_ROLE_ARN =
      "arn:aws:iam::123456789012:role/openclaw-agentcore-execution-role";

    ({ createScopedCredentials } = require("./scoped-credentials"));
  });

  afterEach(() => {
    delete process.env.S3_USER_FILES_BUCKET;
    delete process.env.EXECUTION_ROLE_ARN;
  });

  it("calls STS AssumeRole with session policy", async () => {
    const creds = await createScopedCredentials("telegram_12345", {
      stsClient: _mockStsClient,
    });

    assert.equal(_mockStsClient.send.mock.calls.length, 1);
    const input = _mockStsClient.send.mock.calls[0].arguments[0].input;
    assert.ok(input.RoleArn, "should include RoleArn");
    assert.ok(input.RoleSessionName, "should include RoleSessionName");
    assert.ok(input.Policy, "should include session Policy");

    // Verify session policy is namespace-scoped
    const policy = JSON.parse(input.Policy);
    const resourceStr = JSON.stringify(policy);
    assert.ok(
      resourceStr.includes("telegram_12345"),
      "policy should scope to namespace",
    );
  });

  it("returns credentials object with required fields", async () => {
    const creds = await createScopedCredentials("telegram_12345", {
      stsClient: _mockStsClient,
    });

    assert.ok(creds.accessKeyId, "should have accessKeyId");
    assert.ok(creds.secretAccessKey, "should have secretAccessKey");
    assert.ok(creds.sessionToken, "should have sessionToken");
    assert.ok(creds.expiration, "should have expiration");
  });

  it("sets RoleSessionName with namespace", async () => {
    await createScopedCredentials("slack_U0ABC", {
      stsClient: _mockStsClient,
    });

    const input = _mockStsClient.send.mock.calls[0].arguments[0].input;
    assert.ok(
      input.RoleSessionName.includes("slack_U0ABC"),
      `RoleSessionName should contain namespace, got: ${input.RoleSessionName}`,
    );
  });

  it("sets DurationSeconds to 3600 (max for self-assume)", async () => {
    await createScopedCredentials("telegram_12345", {
      stsClient: _mockStsClient,
    });

    const input = _mockStsClient.send.mock.calls[0].arguments[0].input;
    assert.equal(input.DurationSeconds, 3600);
  });

  it("scopes DynamoDB and scheduler to the deployment resources, not wildcards", async () => {
    process.env.IDENTITY_TABLE_NAME = "openclaw-identity";
    process.env.EVENTBRIDGE_SCHEDULE_GROUP = "openclaw-cron";

    await createScopedCredentials("telegram_12345", {
      stsClient: _mockStsClient,
      internalUserId: "user_abc123",
    });

    const input = _mockStsClient.send.mock.calls[0].arguments[0].input;
    const policy = JSON.parse(input.Policy);

    const dynamoStmt = policy.Statement.find((s) => Array.isArray(s.Action) && s.Action.includes("dynamodb:GetItem"));
    assert.ok(dynamoStmt, "should have DynamoDB actions");
    assert.ok(dynamoStmt.Resource !== "*" && !(Array.isArray(dynamoStmt.Resource) && dynamoStmt.Resource.includes("*")),
      "DynamoDB resource must not be a wildcard");
    assert.ok(dynamoStmt.Condition, "DynamoDB must carry a LeadingKeys condition");

    const ebStmt = policy.Statement.find(
      (s) => Array.isArray(s.Action) && s.Action.includes("scheduler:CreateSchedule"),
    );
    assert.ok(ebStmt, "should have scoped scheduler CRUD actions");
    assert.ok(!ebStmt.Action.includes("scheduler:*"), "must not grant scheduler:*");
    assert.notEqual(ebStmt.Resource, "*", "scheduler resource must not be a wildcard");

    delete process.env.IDENTITY_TABLE_NAME;
    delete process.env.EVENTBRIDGE_SCHEDULE_GROUP;
  });

  it("throws when S3_USER_FILES_BUCKET is missing", async () => {
    delete process.env.S3_USER_FILES_BUCKET;
    await assert.rejects(
      () => createScopedCredentials("telegram_12345", { stsClient: _mockStsClient }),
      /S3_USER_FILES_BUCKET/,
    );
  });

  it("throws when EXECUTION_ROLE_ARN is missing", async () => {
    delete process.env.EXECUTION_ROLE_ARN;
    await assert.rejects(
      () => createScopedCredentials("telegram_12345", { stsClient: _mockStsClient }),
      /EXECUTION_ROLE_ARN/,
    );
  });
});

// --- writeCredentialFiles ---

describe("writeCredentialFiles", () => {
  let writeCredentialFiles;
  let tmpDir;

  const CREDS = {
    accessKeyId: "AKIAIOSFODNN7EXAMPLE",
    secretAccessKey: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
    sessionToken: "FwoGZXIvYXdzEBYaDH...",
    expiration: new Date(Date.now() + 3600000),
  };

  beforeEach(() => {
    delete require.cache[require.resolve("./scoped-credentials")];
    ({ writeCredentialFiles } = require("./scoped-credentials"));
    tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "scoped-creds-test-"));
  });

  afterEach(() => {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  });

  it("writes scoped-creds.json in credential_process format", () => {
    writeCredentialFiles(CREDS, tmpDir);

    const credsPath = path.join(tmpDir, "scoped-creds.json");
    assert.ok(fs.existsSync(credsPath), "scoped-creds.json should exist");

    const content = JSON.parse(fs.readFileSync(credsPath, "utf8"));
    assert.equal(content.Version, 1);
    assert.equal(content.AccessKeyId, CREDS.accessKeyId);
    assert.equal(content.SecretAccessKey, CREDS.secretAccessKey);
    assert.equal(content.SessionToken, CREDS.sessionToken);
    assert.ok(content.Expiration, "should have Expiration");
  });

  it("writes scoped-aws-config with credential_process", () => {
    writeCredentialFiles(CREDS, tmpDir);

    const configPath = path.join(tmpDir, "scoped-aws-config");
    assert.ok(fs.existsSync(configPath), "scoped-aws-config should exist");

    const content = fs.readFileSync(configPath, "utf8");
    assert.ok(content.includes("[default]"), "should have [default] profile");
    assert.ok(
      content.includes("credential_process"),
      "should have credential_process",
    );
    assert.ok(
      content.includes("scoped-creds.json"),
      "should reference scoped-creds.json",
    );
  });

  it("overwrites existing files on refresh", () => {
    writeCredentialFiles(CREDS, tmpDir);

    const updatedCreds = {
      ...CREDS,
      accessKeyId: "AKIAI_REFRESHED",
      expiration: new Date(Date.now() + 7200000),
    };
    writeCredentialFiles(updatedCreds, tmpDir);

    const credsPath = path.join(tmpDir, "scoped-creds.json");
    const content = JSON.parse(fs.readFileSync(credsPath, "utf8"));
    assert.equal(content.AccessKeyId, "AKIAI_REFRESHED");
  });

  it("sets restrictive file permissions on credentials file", () => {
    writeCredentialFiles(CREDS, tmpDir);

    const credsPath = path.join(tmpDir, "scoped-creds.json");
    const stat = fs.statSync(credsPath);
    // Owner read+write only (0o600)
    const mode = stat.mode & 0o777;
    assert.equal(mode, 0o600, `expected 0600, got 0${mode.toString(8)}`);
  });

  it("uses atomic writes (no .tmp files left behind)", () => {
    writeCredentialFiles(CREDS, tmpDir);

    // After a successful write, no .tmp files should remain
    const files = fs.readdirSync(tmpDir);
    const tmpFiles = files.filter((f) => f.endsWith(".tmp"));
    assert.equal(tmpFiles.length, 0, `no .tmp files should remain, got: ${tmpFiles}`);

    // Both final files should exist
    assert.ok(files.includes("scoped-creds.json"), "scoped-creds.json should exist");
    assert.ok(files.includes("scoped-aws-config"), "scoped-aws-config should exist");
  });
});

// --- buildOpenClawEnv ---

describe("buildOpenClawEnv", () => {
  let buildOpenClawEnv;

  beforeEach(() => {
    delete require.cache[require.resolve("./scoped-credentials")];
    ({ buildOpenClawEnv } = require("./scoped-credentials"));
  });

  it("includes AWS_CONFIG_FILE pointing to scoped config", () => {
    const env = buildOpenClawEnv({ credDir: "/tmp/scoped" });
    assert.equal(env.AWS_CONFIG_FILE, "/tmp/scoped/scoped-aws-config");
  });

  it("includes AWS_SDK_LOAD_CONFIG=1", () => {
    const env = buildOpenClawEnv({ credDir: "/tmp/scoped" });
    assert.equal(env.AWS_SDK_LOAD_CONFIG, "1");
  });

  it("does NOT include AWS_ACCESS_KEY_ID", () => {
    const env = buildOpenClawEnv({ credDir: "/tmp/scoped" });
    assert.equal(env.AWS_ACCESS_KEY_ID, undefined);
  });

  it("does NOT include AWS_SECRET_ACCESS_KEY", () => {
    const env = buildOpenClawEnv({ credDir: "/tmp/scoped" });
    assert.equal(env.AWS_SECRET_ACCESS_KEY, undefined);
  });

  it("does NOT include AWS_SESSION_TOKEN", () => {
    const env = buildOpenClawEnv({ credDir: "/tmp/scoped" });
    assert.equal(env.AWS_SESSION_TOKEN, undefined);
  });

  it("does NOT include AWS_CONTAINER_CREDENTIALS_RELATIVE_URI", () => {
    const env = buildOpenClawEnv({ credDir: "/tmp/scoped" });
    assert.equal(env.AWS_CONTAINER_CREDENTIALS_RELATIVE_URI, undefined);
  });

  it("does NOT include AWS_CONTAINER_CREDENTIALS_FULL_URI", () => {
    const env = buildOpenClawEnv({ credDir: "/tmp/scoped" });
    assert.equal(env.AWS_CONTAINER_CREDENTIALS_FULL_URI, undefined);
  });

  it("includes standard env vars and the image compile cache", () => {
    const env = buildOpenClawEnv({
      credDir: "/tmp/scoped",
      baseEnv: {
        PATH: "/usr/bin",
        HOME: "/root",
        NODE_OPTIONS: "--dns-result-order=ipv4first",
        NODE_COMPILE_CACHE: "/app/.compile-cache",
        AWS_REGION: "us-west-2",
      },
    });
    assert.equal(env.PATH, "/usr/bin");
    assert.equal(env.HOME, "/root");
    assert.equal(env.NODE_COMPILE_CACHE, "/app/.compile-cache");
    assert.equal(env.AWS_EC2_METADATA_DISABLED, "true");
    assert.equal(env.AWS_REGION, "us-west-2");
  });

  it("includes S3_USER_FILES_BUCKET from baseEnv", () => {
    const env = buildOpenClawEnv({
      credDir: "/tmp/scoped",
      baseEnv: { S3_USER_FILES_BUCKET: "my-bucket" },
    });
    assert.equal(env.S3_USER_FILES_BUCKET, "my-bucket");
  });

  it("includes EventBridge cron env vars from baseEnv", () => {
    const env = buildOpenClawEnv({
      credDir: "/tmp/scoped",
      baseEnv: {
        EVENTBRIDGE_SCHEDULE_GROUP: "openclaw-cron",
        IDENTITY_TABLE_NAME: "openclaw-identity",
        CRON_LAMBDA_ARN: "arn:aws:lambda:us-west-2:123:function:cron",
        EVENTBRIDGE_ROLE_ARN: "arn:aws:iam::123:role/scheduler",
        CRON_LEAD_TIME_MINUTES: "5",
      },
    });
    assert.equal(env.EVENTBRIDGE_SCHEDULE_GROUP, "openclaw-cron");
    assert.equal(env.IDENTITY_TABLE_NAME, "openclaw-identity");
    assert.equal(env.CRON_LAMBDA_ARN, "arn:aws:lambda:us-west-2:123:function:cron");
    assert.equal(env.EVENTBRIDGE_ROLE_ARN, "arn:aws:iam::123:role/scheduler");
    assert.equal(env.CRON_LEAD_TIME_MINUTES, "5");
  });

  it("includes OPENCLAW_SKIP_CRON=1", () => {
    const env = buildOpenClawEnv({ credDir: "/tmp/scoped" });
    assert.equal(env.OPENCLAW_SKIP_CRON, "1");
  });

  it("includes SUBAGENT_BEDROCK_MODEL_ID from baseEnv", () => {
    const env = buildOpenClawEnv({
      credDir: "/tmp/scoped",
      baseEnv: { SUBAGENT_BEDROCK_MODEL_ID: "global.anthropic.claude-sonnet-5-5" },
    });
    assert.equal(env.SUBAGENT_BEDROCK_MODEL_ID, "global.anthropic.claude-sonnet-5-5");
  });
});

// --- Secrets Manager session policy ---

describe("buildSessionPolicy Secrets Manager", () => {
  let buildSessionPolicy;

  beforeEach(() => {
    ({ buildSessionPolicy } = require("./scoped-credentials"));
  });

  it("restricts Secrets Manager CRUD to the caller's openclaw/user/<namespace>/* path", () => {
    const policy = buildSessionPolicy({
      bucket: "openclaw-user-files-123-us-west-2",
      namespace: "telegram_12345",
      cmkArn: "arn:aws:kms:us-west-2:123:key/abc-123",
      region: "us-west-2",
      account: "123456789012",
    });

    const parsed = JSON.parse(policy);
    const smStmt = parsed.Statement.find(
      (s) => Array.isArray(s.Action) && s.Action.includes("secretsmanager:GetSecretValue"),
    );
    assert.ok(smStmt, "Secrets Manager actions should exist");
    assert.equal(
      smStmt.Resource,
      "arn:aws:secretsmanager:us-west-2:123456789012:secret:openclaw/user/telegram_12345/*",
      "Secrets Manager CRUD must be scoped to this namespace, not a wildcard",
    );
    assert.ok(smStmt.Action.includes("secretsmanager:GetSecretValue"));
    assert.ok(smStmt.Action.includes("secretsmanager:CreateSecret"));
    assert.ok(smStmt.Action.includes("secretsmanager:DeleteSecret"));
    assert.ok(smStmt.Action.includes("secretsmanager:PutSecretValue"));
    assert.ok(smStmt.Action.includes("secretsmanager:TagResource"), "TagResource needed for api-keys skill");
    // ListSecrets does not support resource-level ARNs — it must live in its
    // own statement with Resource:"*", not alongside the CRUD actions.
    assert.ok(!smStmt.Action.includes("secretsmanager:ListSecrets"),
      "ListSecrets must not share the CRUD statement so the CRUD resource stays specific");
  });

  it("ListSecrets stays in a dedicated wildcard statement (service does not support resource ARNs)", () => {
    const policy = buildSessionPolicy({
      bucket: "openclaw-user-files-123-us-west-2",
      namespace: "telegram_12345",
      region: "us-west-2",
      account: "123456789012",
    });

    const parsed = JSON.parse(policy);
    const listStmt = parsed.Statement.find((s) => {
      const actions = Array.isArray(s.Action) ? s.Action : [s.Action];
      return actions.length === 1 && actions[0] === "secretsmanager:ListSecrets";
    });
    assert.ok(listStmt, "Secrets Manager ListSecrets must have its own statement");
    assert.equal(listStmt.Resource, "*", "ListSecrets uses Resource:* because the API does not support ARNs");
  });

  it("Secrets Manager CRUD falls back to a cross-region ARN when region/account are unknown but stays namespace-scoped", () => {
    const policy = buildSessionPolicy({
      bucket: "openclaw-user-files-123-us-west-2",
      namespace: "telegram_12345",
    });

    const parsed = JSON.parse(policy);
    const smStmt = parsed.Statement.find(
      (s) => Array.isArray(s.Action) && s.Action.includes("secretsmanager:GetSecretValue"),
    );
    assert.ok(smStmt, "Secrets Manager actions should exist even without region/account");
    assert.ok(
      typeof smStmt.Resource === "string" && smStmt.Resource.includes("openclaw/user/telegram_12345/"),
      "CRUD resource must still include the namespace prefix, got: " + smStmt.Resource,
    );
    assert.notEqual(smStmt.Resource, "*",
      "Secrets Manager CRUD resource must never be a bare wildcard");
  });

  it("Secrets Manager CRUD resource embeds the exact caller namespace", () => {
    const policy = buildSessionPolicy({
      bucket: "test-bucket",
      namespace: "slack_abc-def",
      region: "ap-southeast-2",
      account: "999888777666",
    });

    const parsed = JSON.parse(policy);
    const smStmt = parsed.Statement.find(
      (s) => Array.isArray(s.Action) && s.Action.includes("secretsmanager:GetSecretValue"),
    );
    assert.ok(smStmt, "Secrets Manager actions should exist");
    assert.equal(
      smStmt.Resource,
      "arn:aws:secretsmanager:ap-southeast-2:999888777666:secret:openclaw/user/slack_abc-def/*",
      "Secrets Manager CRUD resource must be the per-namespace secret path",
    );
  });
});

describe("expiry-aware scoped credentials", () => {
  let dir, now, calls, refresh, published, manager, scoped, savedModule;
  const modulePath = require.resolve("./scoped-credentials");
  const creds = (key = "new", lifetime = 3600000) => ({
    accessKeyId: key, secretAccessKey: "secret", sessionToken: "token", expiration: new Date(now + lifetime),
  });
  beforeEach(() => {
    savedModule = require.cache[modulePath];
    delete require.cache[modulePath];
    scoped = require("./scoped-credentials");
    dir = fs.mkdtempSync(path.join(os.tmpdir(), "creds-v2-"));
    now = Date.now();
    calls = 0;
    published = [];
    refresh = async () => creds(`key-${++calls}`);
  });
  afterEach(() => {
    try {
      manager?.stop();
    } finally {
      manager = null;
      mock.restoreAll();
      if (savedModule) require.cache[modulePath] = savedModule; else delete require.cache[modulePath];
      fs.rmSync(dir, { recursive: true, force: true });
    }
  });
  const create = (options = {}) => {
    manager = scoped.createCredentialManager("telegram_1", {
      credDir: dir, now: () => now, refresh: () => refresh(), onRefresh: (c) => published.push(c.accessKeyId),
      ...options,
    });
    return manager;
  };

  it("exposes the runtime expiry helpers with an explicit safety margin", () => {
    assert.equal(scoped.credentialsExpireAt(creds()), now + 3600000);
    assert.equal(scoped.credentialsExpireAt({ expiration: "invalid" }), 0);
    assert.equal(scoped.credentialsNeedRefresh(creds("key", 1000), { now, minValidityMs: 2000 }), true);
    assert.equal(scoped.credentialsNeedRefresh(creds(), { now, minValidityMs: 2000 }), false);
  });

  it("does no credential IO before activation and refreshes after a wall-clock jump", async () => {
    create();
    assert.equal(calls, 0);
    assert.deepEqual(fs.readdirSync(dir), []);
    await manager.ensureFresh();
    now += 3600001;
    assert.throws(() => manager.getCredentials(), /expired/i);
    await manager.ensureFresh();
    assert.equal(manager.getCredentials().accessKeyId, "key-2");
    assert.deepEqual(published, ["key-1", "key-2"]);
    assert.equal(JSON.parse(fs.readFileSync(path.join(dir, "scoped-creds.json"))).AccessKeyId, "key-2");
  });

  it("coalesces concurrent activation and refresh calls", async () => {
    create();
    let resolve;
    refresh = () => { calls++; return new Promise((r) => { resolve = r; }); };
    const first = manager.ensureFresh();
    const second = manager.ensureFresh();
    await Promise.resolve();
    assert.equal(calls, 1);
    resolve(creds());
    await Promise.all([first, second]);
    assert.equal(published.length, 1);
  });

  it("rejects failed refresh with expired credentials and can retry", async () => {
    create();
    await manager.ensureFresh();
    now += 3600001;
    refresh = async () => { throw new Error("STS unavailable"); };
    await assert.rejects(manager.ensureFresh(), /STS unavailable/);
    assert.throws(() => manager.getCredentials(), /expired/i);
    refresh = async () => creds("recovered");
    await manager.ensureFresh();
    assert.equal(manager.getCredentials().accessKeyId, "recovered");
  });

  it("stopping retires pending refresh before files or callbacks can publish", async () => {
    create();
    let resolve;
    refresh = () => new Promise((r) => { resolve = r; });
    const pending = manager.ensureFresh();
    await Promise.resolve();
    manager.stop();
    resolve(creds());
    await assert.rejects(pending, /stopped/i);
    assert.deepEqual(fs.readdirSync(dir), []);
    assert.deepEqual(published, []);
    await assert.rejects(manager.ensureFresh(), /stopped/i);
  });

  it("does not start a queued refresh after stop", async () => {
    create();
    const pending = manager.ensureFresh();
    manager.stop();
    await assert.rejects(pending, /stopped/i);
    assert.equal(calls, 0);
    assert.deepEqual(published, []);
    assert.deepEqual(fs.readdirSync(dir), []);
  });

  it("does not publish after stop while asynchronous preparation is pending", async () => {
    let started, finish;
    const preparationStarted = new Promise((resolve) => { started = resolve; });
    const prepared = new Promise((resolve) => { finish = resolve; });
    create({
      prepareRefresh: async () => { started(); return prepared; },
      onRefresh: (next, value) => published.push([next.accessKeyId, value]),
    });
    const pending = manager.ensureFresh();
    await Promise.race([preparationStarted, pending]);
    assert.deepEqual(published, []);
    assert.deepEqual(fs.readdirSync(dir), []);
    manager.stop();
    finish("prepared");
    await assert.rejects(pending, /stopped/i);
    assert.deepEqual(published, []);
    assert.deepEqual(fs.readdirSync(dir), []);
  });

  it("drain fences child publication while request and persistence share pending preparation", async () => {
    let started, finish;
    const preparationStarted = new Promise((resolve) => { started = resolve; });
    const prepared = new Promise((resolve) => { finish = resolve; });
    create({ prepareRefresh: async () => { started(); await prepared; } });
    const request = manager.ensureFresh();
    const rejected = assert.rejects(request, /draining/i);
    await preparationStarted;
    const save = manager.ensureFresh({ forPersistence: true, minValidityMs: 60000 });
    manager.beginDrain();
    finish();
    await rejected;
    assert.equal((await save).accessKeyId, "key-1");
    assert.equal(calls, 1);
    assert.deepEqual(published, []);
    assert.deepEqual(fs.readdirSync(dir), []);
    assert.throws(() => manager.getCredentials(), /draining/i);
  });

  for (const acquisitionFails of [false, true]) {
    it(`persistence joins pending acquisition across drain${acquisitionFails ? " and retries a failed acquisition" : ""}`, async () => {
      let finish, reject;
      create();
      refresh = () => {
        calls++;
        return new Promise((resolve, fail) => { finish = resolve; reject = fail; });
      };
      const request = manager.ensureFresh();
      const rejected = assert.rejects(request, acquisitionFails ? /STS unavailable/ : /draining/);
      await Promise.resolve();
      manager.beginDrain();
      const save = manager.ensureFresh({ forPersistence: true, minValidityMs: 60000 });
      if (acquisitionFails) {
        const failedSave = assert.rejects(save, /STS unavailable/);
        reject(new Error("STS unavailable"));
        await Promise.all([rejected, failedSave]);
        refresh = async () => { calls++; return creds("recovered"); };
        assert.equal((await manager.ensureFresh({ forPersistence: true })).accessKeyId, "recovered");
        assert.equal(calls, 2);
      } else {
        finish(creds("draining"));
        assert.equal((await save).accessKeyId, "draining");
        await rejected;
        assert.equal(calls, 1);
      }
      assert.deepEqual(published, []);
      assert.deepEqual(fs.readdirSync(dir), []);
    });
  }

  it("stop fences a draining refresh while asynchronous preparation is pending", async () => {
    let started, finish;
    const preparationStarted = new Promise((resolve) => { started = resolve; });
    const prepared = new Promise((resolve) => { finish = resolve; });
    create({ prepareRefresh: async () => { started(); await prepared; } });
    manager.beginDrain();
    const save = manager.ensureFresh({ forPersistence: true, minValidityMs: 60000 });
    await preparationStarted;
    manager.stop();
    finish();
    await assert.rejects(save, /stopped/i);
    assert.deepEqual(published, []);
    assert.deepEqual(fs.readdirSync(dir), []);
  });

  it("checks each concurrent caller's validity margin after a shared refresh", async () => {
    let finish;
    create();
    refresh = () => {
      calls++;
      return new Promise((resolve) => { finish = resolve; });
    };
    const save = manager.ensureFresh({ forPersistence: true, minValidityMs: 60000 });
    const request = manager.ensureFresh({ minValidityMs: 680000 });
    const rejected = assert.rejects(request, /expired/i);
    await Promise.resolve();
    finish(creds("short", 120000));
    assert.equal((await save).accessKeyId, "short");
    await rejected;
    assert.equal(calls, 1);
  });

  it("publishes prepared credentials synchronously after preparation succeeds", async () => {
    const prepared = { ready: true };
    create({
      prepareRefresh: async (next) => {
        assert.deepEqual(fs.readdirSync(dir), []);
        assert.equal(next.accessKeyId, "key-1");
        return prepared;
      },
      onRefresh: (next, value) => {
        assert.equal(value, prepared);
        published.push(next.accessKeyId);
      },
    });
    await manager.ensureFresh();
    assert.deepEqual(published, ["key-1"]);
    assert.equal(manager.getCredentials().accessKeyId, "key-1");
    assert.equal(JSON.parse(fs.readFileSync(path.join(dir, "scoped-creds.json"))).AccessKeyId, "key-1");
  });

  it("rejects asynchronous publication callbacks before they can start", async () => {
    let finish;
    const deferred = new Promise((resolve) => { finish = resolve; });
    const onRefresh = async (next) => {
      await deferred;
      published.push(next.accessKeyId);
    };
    assert.throws(() => create({ onRefresh }), /onRefresh.*synchronous.*prepareRefresh/i);
    finish();
    await Promise.resolve();
    assert.equal(calls, 0);
    assert.deepEqual(published, []);
    assert.deepEqual(fs.readdirSync(dir), []);
  });

  it("rejects preparation failures and credentials that expire during preparation", async () => {
    let fail = true;
    create({
      prepareRefresh: async () => {
        if (fail) throw new Error("preparation failed");
        now += 3600001;
      },
    });
    await assert.rejects(manager.ensureFresh(), /preparation failed/);
    fail = false;
    await assert.rejects(manager.ensureFresh(), /expired/i);
    assert.deepEqual(published, []);
    assert.deepEqual(fs.readdirSync(dir), []);
  });

  it("rejects invalid or expired credentials before replacing existing files", () => {
    scoped.writeCredentialFiles(creds("good"), dir, { now: () => now });
    const original = fs.readFileSync(path.join(dir, "scoped-creds.json"), "utf8");
    assert.throws(() => scoped.writeCredentialFiles(creds("bad", -1), dir, { now: () => now }), /expired/i);
    assert.throws(() => scoped.writeCredentialFiles(creds("bad", -1), dir), /expired/i);
    assert.throws(() => scoped.writeCredentialFiles({ ...creds(), sessionToken: null }, dir, { now: () => now }), /sessionToken/i);
    assert.equal(fs.readFileSync(path.join(dir, "scoped-creds.json"), "utf8"), original);
  });

  it("uses private atomic files and removes its staging file after a failed rename", () => {
    scoped.writeCredentialFiles(creds("good"), dir);
    const file = path.join(dir, "scoped-creds.json");
    const original = fs.readFileSync(file, "utf8");
    const rename = fs.renameSync;
    mock.method(fs, "renameSync", (src, dst) => {
      if (dst === file) {
        assert.equal(fs.readFileSync(file, "utf8"), original);
        assert.equal(JSON.parse(fs.readFileSync(src)).AccessKeyId, "next");
        throw new Error("rename failed");
      }
      return rename(src, dst);
    });
    assert.throws(() => scoped.writeCredentialFiles(creds("next"), dir), /rename failed/);
    assert.equal(fs.readFileSync(file, "utf8"), original);
    assert.equal(fs.statSync(file).mode & 0o777, 0o600);
    assert.deepEqual(fs.readdirSync(dir).sort(), ["scoped-aws-config", "scoped-creds.json"]);
  });
});
