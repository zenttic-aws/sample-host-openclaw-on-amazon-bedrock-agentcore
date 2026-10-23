/**
 * Scoped S3 Credentials — Per-user IAM scoping via STS session policies.
 *
 * Creates STS AssumeRole session credentials that restrict S3 access to a
 * single user's namespace prefix, writes them to a credential_process file,
 * and builds a child environment that points the AWS SDK/CLI at that file
 * instead of the container's ambient credentials.
 *
 * Threat-model caveat — read before extending this module:
 *
 *   The child OpenClaw process currently runs as uid 0 in the same PID,
 *   mount and network namespace as this contract server (bridge/Dockerfile
 *   has no USER directive; bridge/entrypoint.sh does `exec node
 *   agentcore-contract.js` so the contract server is PID 1). A root process
 *   in that namespace can read /proc/1/environ or reach the container
 *   credential endpoint directly (AWS_EC2_METADATA_DISABLED is only an SDK
 *   hint and no network rule blocks 169.254.170.2 / 169.254.169.254). That
 *   means stripping credential environment variables from the child env
 *   does NOT, on its own, prevent an attacker who achieves code execution
 *   through OpenClaw's exec tool from recovering the full execution-role
 *   credentials.
 *
 *   Real cross-user isolation therefore requires EITHER (a) running the
 *   OpenClaw child under a dedicated unprivileged uid with hidepid / a
 *   separate PID namespace plus an iptables owner-match rule blocking the
 *   container credential endpoint for that uid, OR (b) exchanging the
 *   ambient credentials once at bootstrap, scrubbing
 *   AWS_CONTAINER_CREDENTIALS_* / AWS_CONTAINER_AUTHORIZATION_TOKEN* from
 *   this process and dropping network access to the credential endpoint.
 *   Until one of those holds, treat the per-user AgentCore microVM as the
 *   enforced tenant boundary and treat the child env filter below as a
 *   defence-in-depth hardening against accidental SDK fallback — not as
 *   the isolation mechanism.
 *
 * Usage:
 *   const { createScopedCredentials, writeCredentialFiles, buildOpenClawEnv } = require("./scoped-credentials");
 *   const creds = await createScopedCredentials(namespace);
 *   writeCredentialFiles(creds, "/tmp/scoped");
 *   const env = buildOpenClawEnv({ credDir: "/tmp/scoped", baseEnv: process.env });
 *   spawn("openclaw", args, { env });
 */

const fs = require("fs");
const path = require("path");
const { isAsyncFunction } = require("util").types;

const VALID_NAMESPACE = /^[a-zA-Z][a-zA-Z0-9_-]{1,64}$/;

function validateNamespace(namespace) {
  if (typeof namespace !== "string" || !VALID_NAMESPACE.test(namespace)) {
    throw new Error(`Invalid namespace "${namespace}" — must match ${VALID_NAMESPACE}`);
  }
  return namespace;
}

function credentialsExpireAt(creds) {
  const expiresAt = new Date(creds?.expiration).getTime();
  return Number.isFinite(expiresAt) ? expiresAt : 0;
}

function credentialsNeedRefresh(creds, { now = Date.now(), minValidityMs = 5 * 60 * 1000 } = {}) {
  const timestamp = typeof now === "function" ? now() : now;
  return !creds || credentialsExpireAt(creds) <= timestamp + minValidityMs;
}

function assertCredentialsFresh(creds, { now = Date.now, minValidityMs = 0 } = {}) {
  for (const key of ["accessKeyId", "secretAccessKey", "sessionToken"]) {
    if (!creds || typeof creds[key] !== "string" || !creds[key]) {
      throw new Error(`Scoped credentials: ${key} is required`);
    }
  }
  if (credentialsNeedRefresh(creds, { now, minValidityMs })) {
    throw new Error("Scoped credentials expired or expiration is invalid");
  }
  return creds;
}

// ENV vars that MUST be excluded from the OpenClaw child so the AWS SDK/CLI
// in that child cannot resolve ambient container credentials through its
// default provider chain. This is defence-in-depth: see the module header
// for why a stripped env alone is NOT a tenant-isolation boundary when the
// child shares a uid and PID namespace with this contract server. Every
// known AWS credential source the SDK consults is listed here, including
// the authorization-token variables used with the container credential
// endpoint (previously missing — their presence let the child reach the
// endpoint directly). Keep this list in sync with the lists in
// bridge/openclaw-worker-owner.js, bridge/openclaw-preinit.mjs,
// bridge/live-gateway-seed-common.mjs and bridge/sqlite-receiver-control.mjs.
const CREDENTIAL_ENV_BLOCKLIST = [
  "AWS_ACCESS_KEY_ID",
  "AWS_SECRET_ACCESS_KEY",
  "AWS_SESSION_TOKEN",
  "AWS_SECURITY_TOKEN",
  "AWS_CONTAINER_CREDENTIALS_RELATIVE_URI",
  "AWS_CONTAINER_CREDENTIALS_FULL_URI",
  "AWS_CONTAINER_AUTHORIZATION_TOKEN",
  "AWS_CONTAINER_AUTHORIZATION_TOKEN_FILE",
  "AWS_WEB_IDENTITY_TOKEN_FILE",
  "AWS_ROLE_ARN",
  "AWS_ROLE_SESSION_NAME",
  "AWS_SHARED_CREDENTIALS_FILE",
  "AWS_PROFILE",
];

// ENV vars forwarded from baseEnv to OpenClaw process
const FORWARDED_ENV_KEYS = [
  "PATH",
  "HOME",
  "NODE_PATH",
  "NODE_OPTIONS",
  "NODE_COMPILE_CACHE",
  "AWS_REGION",
  "S3_USER_FILES_BUCKET",
  "USER_ID",
  "SUBAGENT_BEDROCK_MODEL_ID",
  // EventBridge cron skill
  "EVENTBRIDGE_SCHEDULE_GROUP",
  "IDENTITY_TABLE_NAME",
  "CRON_LAMBDA_ARN",
  "EVENTBRIDGE_ROLE_ARN",
  "CRON_LEAD_TIME_MINUTES",
  // User identity — skills like agentcore-browser read USER_ID from env
  "USER_ID",
  "INTERNAL_USER_ID",
];

/**
 * Build an IAM session policy JSON string that scopes S3 access to a user's namespace.
 *
 * @param {object} opts
 * @param {string} opts.bucket - S3 bucket name
 * @param {string} opts.namespace - User namespace (e.g. "telegram_12345")
 * @param {string} [opts.cmkArn] - KMS CMK ARN for encrypted bucket
 * @param {string} [opts.eventbridgeRoleArn] - EventBridge scheduler role ARN for iam:PassRole
 * @param {string} [opts.identityTableArn] - DynamoDB identity table ARN (scopes DynamoDB access)
 * @param {string} [opts.scheduleGroupArn] - EventBridge schedule group ARN (scopes scheduler access)
 * @returns {string} JSON policy document
 */
function buildSessionPolicy({ bucket, namespace, actorId, internalUserId, cmkArn, eventbridgeRoleArn, identityTableArn, scheduleGroupArn, region, account }) {
  validateNamespace(namespace);

  // EventBridge Scheduler resources:
  // - CRUD actions (Create/Update/Delete/Get) operate on individual schedules
  //   ARN format: arn:aws:scheduler:REGION:ACCOUNT:schedule/GROUP/SCHEDULE
  // - ListSchedules operates on the schedule-group resource
  const scheduleCrudArn = scheduleGroupArn
    ? scheduleGroupArn.replace(":schedule-group/", ":schedule/") + "/*"
    : "*";
  const scheduleListArn = scheduleGroupArn || "*";

  // DynamoDB resources: table + GSI indexes
  const dynamoResources = identityTableArn
    ? [identityTableArn, `${identityTableArn}/index/*`]
    : "*";

  // Build a minimal session policy that fits within the 2048-byte AWS packed limit.
  // The execution role (attached to the runtime) provides the broad permissions.
  // This session policy only RESTRICTS — it cannot grant permissions the role
  // doesn't have. We scope S3 and Secrets Manager to the caller's namespace so
  // a compromised agent (prompt injection, user-supplied skill arguments) cannot
  // reach another tenant's data even if it bypasses the application-level checks.
  //
  // Secrets Manager CRUD actions are scoped to
  //   arn:aws:secretsmanager:<region>:<account>:secret:openclaw/user/<namespace>/*
  // which matches the layout used by bridge/skills/api-keys/*. ListSecrets does
  // NOT support resource-level restrictions (AWS API limitation), so it stays
  // wildcard in its own statement; the skill filters results by namespace prefix.
  const secretsResourceArn = (region && account)
    ? `arn:aws:secretsmanager:${region}:${account}:secret:openclaw/user/${namespace}/*`
    : "*";

  const policy = {
    Version: "2012-10-17",
    Statement: [
      {
        Effect: "Allow",
        // AbortMultipartUpload: workspace-sync uploads large SQLite snapshots
        // as multipart uploads and aborts a failed one so no billed parts linger.
        Action: ["s3:GetObject", "s3:PutObject", "s3:DeleteObject", "s3:AbortMultipartUpload"],
        Resource: `arn:aws:s3:::${bucket}/${namespace}/*`,
      },
      {
        Effect: "Allow",
        Action: "s3:ListBucket",
        Resource: `arn:aws:s3:::${bucket}`,
        // Restrict ListObjectsV2 to this user's namespace: without this
        // condition s3:ListBucket would enumerate every tenant's object
        // keys (incl. _uploads/ filenames and agent-state files such as
        // IDENTITY.md/MEMORY.md), even though object reads are already
        // prefix-scoped above.
        Condition: {
          StringLike: { "s3:prefix": [`${namespace}/*`, `${namespace}/`] },
        },
      },
      // Scheduler, DynamoDB, KMS, PassRole — allowed by the execution role;
      // application-level checks in skill scripts enforce namespace isolation.
      // Secrets Manager CRUD is namespace-scoped below (defence in depth).
      {
        Effect: "Allow",
        Action: [
          "scheduler:*",
          "dynamodb:GetItem", "dynamodb:PutItem", "dynamodb:UpdateItem", "dynamodb:DeleteItem", "dynamodb:Query",
          "kms:Decrypt", "kms:GenerateDataKey",
          "iam:PassRole",
        ],
        Resource: "*",
      },
      {
        Effect: "Allow",
        Action: [
          "secretsmanager:GetSecretValue",
          "secretsmanager:PutSecretValue",
          "secretsmanager:CreateSecret",
          "secretsmanager:DeleteSecret",
          "secretsmanager:TagResource",
        ],
        Resource: secretsResourceArn,
      },
      {
        Effect: "Allow",
        // ListSecrets does not support resource-level restrictions. The caller
        // filters by name prefix (openclaw/user/<namespace>/) in skill scripts.
        Action: "secretsmanager:ListSecrets",
        Resource: "*",
      },
    ],
  };

  return JSON.stringify(policy);
}

/**
 * Create scoped S3 credentials via STS AssumeRole with a session policy.
 *
 * @param {string} namespace - User namespace (e.g. "telegram_12345")
 * @param {object} [opts] - Options
 * @param {object} [opts.stsClient] - Pre-configured STS client (for testing)
 * @param {string} [opts.internalUserId] - Internal user ID (e.g. "user_abc123") for DynamoDB CRON#/SESSION access
 * @returns {Promise<{accessKeyId: string, secretAccessKey: string, sessionToken: string, expiration: Date}>}
 */
async function createScopedCredentials(namespace, opts = {}) {
  validateNamespace(namespace);
  const bucket = process.env.S3_USER_FILES_BUCKET;
  const roleArn = process.env.EXECUTION_ROLE_ARN;
  const cmkArn = process.env.CMK_ARN;
  const eventbridgeRoleArn = process.env.EVENTBRIDGE_ROLE_ARN;
  const region = process.env.AWS_REGION;

  if (!bucket) {
    throw new Error("createScopedCredentials: S3_USER_FILES_BUCKET is required");
  }
  if (!roleArn) {
    throw new Error("createScopedCredentials: EXECUTION_ROLE_ARN is required");
  }

  // Extract account ID from role ARN (arn:aws:iam::ACCOUNT:role/NAME)
  const arnParts = roleArn.split(":");
  const account = arnParts.length >= 5 ? arnParts[4] : null;

  // Construct scoped resource ARNs when account and region are available
  const identityTableName = process.env.IDENTITY_TABLE_NAME;
  const scheduleGroup = process.env.EVENTBRIDGE_SCHEDULE_GROUP;

  const identityTableArn = (account && region && identityTableName)
    ? `arn:aws:dynamodb:${region}:${account}:table/${identityTableName}`
    : undefined;
  const scheduleGroupArn = (account && region && scheduleGroup)
    ? `arn:aws:scheduler:${region}:${account}:schedule-group/${scheduleGroup}`
    : undefined;

  // Derive actorId from namespace (namespace uses underscores, actorId uses colons)
  // e.g. namespace "telegram_123456" -> actorId "telegram:123456"
  const actorId = namespace.replace(/_/, ":");

  const sessionPolicy = buildSessionPolicy({
    bucket, namespace, actorId, internalUserId: opts.internalUserId,
    cmkArn, eventbridgeRoleArn,
    identityTableArn, scheduleGroupArn, region, account,
  });

  const commandInput = {
    RoleArn: roleArn,
    RoleSessionName: `scoped-${namespace}`.slice(0, 64),
    DurationSeconds: 3600, // Max for self-assume (role chaining)
    Policy: sessionPolicy,
  };

  let stsClient = opts.stsClient;
  let command;

  if (stsClient) {
    // Mock/test path — use plain object with input property (avoids SDK require)
    command = { input: commandInput };
  } else {
    // Production path — use real STS SDK
    const { STSClient, AssumeRoleCommand } = require("@aws-sdk/client-sts");
    stsClient = new STSClient({ region: process.env.AWS_REGION });
    command = new AssumeRoleCommand(commandInput);
  }

  const resp = await stsClient.send(command);

  const creds = {
    accessKeyId: resp.Credentials.AccessKeyId,
    secretAccessKey: resp.Credentials.SecretAccessKey,
    sessionToken: resp.Credentials.SessionToken,
    expiration: resp.Credentials.Expiration,
  };
  assertCredentialsFresh(creds, { now: opts.now });
  return creds;
}

function writePrivateFileAtomic(file, content) {
  const tmp = `${file}.tmp-${process.pid}-${require("crypto").randomUUID()}`;
  try {
    fs.writeFileSync(tmp, content, { mode: 0o600, flag: "wx" });
    fs.renameSync(tmp, file);
  } finally {
    try { fs.unlinkSync(tmp); } catch (err) { if (err.code !== "ENOENT") throw err; }
  }
}

/**
 * Write credential files for AWS SDK credential_process integration.
 *
 * Creates two files:
 * - scoped-creds.json: Credential process output format (Version 1)
 * - scoped-aws-config: AWS config file with credential_process directive
 *
 * @param {object} creds - Credentials from createScopedCredentials()
 * @param {string} dir - Directory to write files in
 */
function writeCredentialFiles(creds, dir, { now = Date.now } = {}) {
  assertCredentialsFresh(creds, { now });
  fs.mkdirSync(dir, { recursive: true, mode: 0o700 });

  const credsJson = {
    Version: 1,
    AccessKeyId: creds.accessKeyId,
    SecretAccessKey: creds.secretAccessKey,
    SessionToken: creds.sessionToken,
    Expiration: creds.expiration instanceof Date
      ? creds.expiration.toISOString()
      : creds.expiration,
  };

  // Atomic write: write to .tmp then rename — prevents credential_process
  // from reading a partially-written file during refresh.
  const credsPath = path.join(dir, "scoped-creds.json");
  writePrivateFileAtomic(credsPath, JSON.stringify(credsJson, null, 2));

  const configContent = [
    "[default]",
    `credential_process = /bin/cat "${credsPath}"`,
    `region = ${process.env.AWS_REGION || "us-west-2"}`,
    "",
  ].join("\n");

  const configPath = path.join(dir, "scoped-aws-config");
  writePrivateFileAtomic(configPath, configContent);
}

// Requests and persistence share refreshes; drain keeps only persistence active.
function createCredentialManager(namespace, {
  credDir, internalUserId, stsClient, onRefresh = () => {}, now = Date.now,
  prepareRefresh = () => {},
  refreshBeforeMs = 5 * 60 * 1000,
  refresh = () => createScopedCredentials(namespace, { internalUserId, stsClient, now }),
} = {}) {
  validateNamespace(namespace);
  if (!Number.isFinite(refreshBeforeMs) || refreshBeforeMs < 0) throw new Error("Invalid refreshBeforeMs");
  const callbackError = "onRefresh must be synchronous; use prepareRefresh for asynchronous preparation";
  if (typeof onRefresh !== "function" || isAsyncFunction(onRefresh)) throw new TypeError(callbackError);
  if (typeof prepareRefresh !== "function") throw new TypeError("prepareRefresh must be a function");
  let credentials = null;
  let inFlight = null;
  let stopped = false;
  let draining = false;
  function assertActive() {
    if (stopped) throw new Error("Scoped credential manager stopped");
  }
  function assertAccess(forPersistence = false) {
    assertActive();
    if (draining && !forPersistence) throw new Error("Scoped credential manager draining");
  }
  function getCredentials() {
    assertAccess();
    return assertCredentialsFresh(credentials, { now });
  }
  async function ensureFresh({ forPersistence = false, minValidityMs = refreshBeforeMs } = {}) {
    assertAccess(forPersistence === true);
    if (!Number.isFinite(minValidityMs) || minValidityMs < 0) throw new Error("Invalid minValidityMs");
    if (!inFlight && credentials && new Date(credentials.expiration).getTime() > now() + minValidityMs) {
      return assertCredentialsFresh(credentials, { now, minValidityMs });
    }
    inFlight ||= Promise.resolve().then(async () => {
      assertActive();
      const next = await refresh();
      assertActive();
      assertCredentialsFresh(next, { now, minValidityMs });
      const prepared = await prepareRefresh(next);
      assertActive();
      assertCredentialsFresh(next, { now, minValidityMs });
      // Draining saves use memory only; stopped or aborted children get no new files.
      if (!draining) {
        // No await between the stop check and synchronous publication.
        if (credDir) writeCredentialFiles(next, credDir, { now });
        const result = onRefresh(next, prepared);
        if (result && typeof result.then === "function") {
          Promise.resolve(result).catch(() => {});
          throw new TypeError(callbackError);
        }
      }
      assertActive();
      credentials = Object.freeze({ ...next });
      return credentials;
    }).finally(() => { inFlight = null; });
    const refreshed = await inFlight;
    assertAccess(forPersistence === true);
    return assertCredentialsFresh(refreshed, { now, minValidityMs });
  }
  function beginDrain() {
    draining = true;
  }
  function stop() {
    stopped = true;
    credentials = null;
  }
  return { ensureFresh, getCredentials, beginDrain, stop };
}

/**
 * Build a clean environment for the OpenClaw child process.
 *
 * Includes scoped credential config and app env vars, and strips every
 * known AWS credential source (CREDENTIAL_ENV_BLOCKLIST) from the forwarded
 * variables so the SDK/CLI inside the child defaults to the scoped
 * credential_process file. This filter is defence-in-depth only: it does
 * NOT, by itself, prevent a child that runs as root in the same PID
 * namespace as this contract server from reading /proc/1/environ or
 * contacting the container credential endpoint. See the module header for
 * the required container-level controls (dedicated uid, hidepid / PID
 * namespace, iptables owner-match on the credential endpoint, or ambient
 * credentials scrubbed from this process after bootstrap).
 *
 * @param {object} opts
 * @param {string} opts.credDir - Directory containing scoped credential files
 * @param {object} [opts.baseEnv] - Base environment to extract forwarded vars from
 * @returns {object} Environment variables for spawn()
 */
function buildOpenClawEnv({ credDir, baseEnv = {} }) {
  const env = { AWS_EC2_METADATA_DISABLED: "true" };

  // Forward allowed env vars from base environment
  for (const key of FORWARDED_ENV_KEYS) {
    if (baseEnv[key] !== undefined) {
      env[key] = baseEnv[key];
    }
  }

  // Scoped credentials via credential_process (when credDir is available)
  if (credDir) {
    env.AWS_CONFIG_FILE = path.join(credDir, "scoped-aws-config");
    env.AWS_SDK_LOAD_CONFIG = "1";
  }
  // When credDir is null/undefined, OpenClaw gets zero AWS access —
  // no credential_process, no credential env vars, tools fail gracefully.

  // OpenClaw internal
  env.OPENCLAW_SKIP_CRON = "1";

  // Ensure no credential env vars leak through
  for (const key of CREDENTIAL_ENV_BLOCKLIST) {
    delete env[key];
  }

  return env;
}

module.exports = {
  credentialsExpireAt,
  credentialsNeedRefresh,
  validateNamespace,
  assertCredentialsFresh,
  createCredentialManager,
  buildSessionPolicy,
  createScopedCredentials,
  writeCredentialFiles,
  buildOpenClawEnv,
  CREDENTIAL_ENV_BLOCKLIST,
  FORWARDED_ENV_KEYS,
};
