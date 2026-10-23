/**
 * Shared utilities for eventbridge-cron skill.
 */
const { DynamoDBClient } = require("@aws-sdk/client-dynamodb");
const { DynamoDBDocumentClient, PutCommand, GetCommand, DeleteCommand, QueryCommand, UpdateCommand } = require("@aws-sdk/lib-dynamodb");
const fs = require("fs");

const REGION = process.env.AWS_REGION;
if (!REGION) {
  console.error("Error: AWS_REGION environment variable is not set.");
  process.exit(1);
}

const SCHEDULE_GROUP = process.env.EVENTBRIDGE_SCHEDULE_GROUP || "openclaw-cron";
const CRON_LAMBDA_ARN = process.env.CRON_LAMBDA_ARN;
const EVENTBRIDGE_ROLE_ARN = process.env.EVENTBRIDGE_ROLE_ARN;
const IDENTITY_TABLE_NAME = process.env.IDENTITY_TABLE_NAME;

/**
 * Validate that userId is present, not the default-user fallback,
 * and matches the expected channel_identifier namespace pattern.
 */
function validateUserId(userId) {
  if (!userId) {
    console.error("Error: user_id argument is required.");
    process.exit(1);
  }
  if (userId === "default-user" || userId === "default_user") {
    console.error(
      "Error: Cannot operate on schedules for default-user. User identity was not resolved.",
    );
    process.exit(1);
  }
  const VALID_NAMESPACE =
    /^(telegram|slack|discord|whatsapp|feishu|line)_[a-zA-Z0-9_-]{1,64}$/;
  if (!VALID_NAMESPACE.test(userId)) {
    console.error(
      `Error: Invalid user_id "${userId}". Must match channel_identifier format (e.g., telegram_123456, slack_username).`,
    );
    process.exit(1);
  }
}

/**
 * Validate required environment variables for schedule operations.
 */
function validateEnv() {
  if (!CRON_LAMBDA_ARN) {
    console.error("Error: CRON_LAMBDA_ARN environment variable not set.");
    process.exit(1);
  }
  if (!EVENTBRIDGE_ROLE_ARN) {
    console.error("Error: EVENTBRIDGE_ROLE_ARN environment variable not set.");
    process.exit(1);
  }
  if (!IDENTITY_TABLE_NAME) {
    console.error("Error: IDENTITY_TABLE_NAME environment variable not set.");
    process.exit(1);
  }
}

/**
 * Validate a schedule expression: cron(...), rate(...), or at(...).
 * - cron() must have exactly 6 space-separated fields (Minutes Hours Day Month DayOfWeek Year)
 * - rate() must match rate(N unit) format with minimum 5-minute interval
 * - at() must match at(YYYY-MM-DDTHH:MM:SS) format
 *
 * The cron minute field is parsed as a positive frequency check (see
 * lambda/gateway_tools/eventbridge_cron/index.js:cronMinuteMinInterval) rather
 * than compared against a denylist, so EventBridge-equivalent every-minute
 * expressions such as `0-59`, `0/1`, `*\/2`, or an exhaustive comma list are
 * all refused on both surfaces.
 */
const MIN_INTERVAL_MINUTES = 5;
const MAX_SCHEDULES_PER_USER = 20;

function cronMinuteMinInterval(field) {
  if (typeof field !== "string" || field.length === 0) {
    throw new Error("cron() minute field is required");
  }
  if (field === "*") return 1;
  const stepStar = field.match(/^\*\/(\d+)$/);
  if (stepStar) {
    const n = parseInt(stepStar[1], 10);
    if (!Number.isInteger(n) || n < 1 || n > 59) {
      throw new Error(`Unsupported cron minute field "${field}"`);
    }
    return n;
  }
  if (/^\d+$/.test(field)) {
    const n = parseInt(field, 10);
    if (n < 0 || n > 59) throw new Error(`Unsupported cron minute field "${field}"`);
    return 60;
  }
  if (/^\d+(,\d+)+$/.test(field)) {
    const parts = field.split(",").map((p) => parseInt(p, 10));
    for (const n of parts) {
      if (!Number.isInteger(n) || n < 0 || n > 59) {
        throw new Error(`Unsupported cron minute field "${field}"`);
      }
    }
    const sorted = Array.from(new Set(parts)).sort((a, b) => a - b);
    if (sorted.length !== parts.length) {
      throw new Error(`Unsupported cron minute field "${field}"`);
    }
    if (sorted.length === 1) return 60;
    let min = 60 + sorted[0] - sorted[sorted.length - 1];
    for (let i = 1; i < sorted.length; i++) {
      const gap = sorted[i] - sorted[i - 1];
      if (gap < min) min = gap;
    }
    return min;
  }
  // Ranges and step-on-ranges are rejected: `0-59`, `0-59/5`, `10-20`, etc.
  throw new Error(`Unsupported cron minute field "${field}"`);
}

function validateExpression(expression) {
  const cronRegex = /^cron\((.+)\)$/;
  const rateRegex = /^rate\(\d+\s+(minute|minutes|hour|hours|day|days)\)$/;
  const atRegex = /^at\((\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})\)$/;

  if (atRegex.test(expression)) {
    // at() expression — validate the datetime is parseable
    const dateStr = expression.match(atRegex)[1];
    const parsed = new Date(dateStr);
    if (isNaN(parsed.getTime())) {
      console.error(
        `Error: Invalid at() datetime "${dateStr}". ` +
        `Must be a valid ISO 8601 datetime: at(YYYY-MM-DDTHH:MM:SS)`,
      );
      process.exit(1);
    }
    return;
  }

  if (rateRegex.test(expression)) {
    // Enforce minimum 5-minute interval for rate expressions
    const rateMatch = expression.match(/^rate\((\d+)\s+(minute|minutes)\)$/);
    if (rateMatch && parseInt(rateMatch[1], 10) < MIN_INTERVAL_MINUTES) {
      console.error(
        `Error: Minimum rate interval is ${MIN_INTERVAL_MINUTES} minutes. ` +
        `Use rate(${MIN_INTERVAL_MINUTES} minutes) or higher to prevent cost abuse.`,
      );
      process.exit(1);
    }
    return;
  }

  const cronMatch = expression.match(cronRegex);
  if (cronMatch) {
    // Validate cron has exactly 6 fields
    const fields = cronMatch[1].trim().split(/\s+/);
    if (fields.length !== 6) {
      console.error(
        `Error: cron() expression must have exactly 6 fields, got ${fields.length}.\n` +
        `Format: cron(Minutes Hours Day-of-month Month Day-of-week Year)\n` +
        `Example: cron(0 9 * * ? *)`,
      );
      process.exit(1);
    }

    // Positive frequency check on the minute field so EventBridge-equivalent
    // every-minute expressions (`0-59`, `0/1`, `0,1,2,...,59`) are rejected,
    // not just the two literal shapes an earlier denylist happened to list.
    const minutesField = fields[0];
    let interval;
    try {
      interval = cronMinuteMinInterval(minutesField);
    } catch {
      console.error(
        `Error: Unsupported or every-minute cron minute field "${minutesField}". ` +
        `Minimum interval is ${MIN_INTERVAL_MINUTES} minutes. ` +
        `Use "*/N" with N>=${MIN_INTERVAL_MINUTES}, a single minute (e.g. "0"), ` +
        `or an explicit comma list whose gaps are all >=${MIN_INTERVAL_MINUTES}.`,
      );
      process.exit(1);
    }
    if (interval < MIN_INTERVAL_MINUTES) {
      console.error(
        `Error: Every-minute cron expressions are not allowed. ` +
        `Minimum interval is ${MIN_INTERVAL_MINUTES} minutes. Use */${MIN_INTERVAL_MINUTES} or higher.`,
      );
      process.exit(1);
    }
    return;
  }

  // No recognized format
  console.error(
    `Error: Invalid expression "${expression}". ` +
    `Must be cron(...), rate(...), or at(...) format.\n` +
    `Examples: cron(0 9 * * ? *), rate(1 hour), at(2025-12-31T23:59:00)`,
  );
  process.exit(1);
}

/**
 * Validate an IANA timezone string using Intl.DateTimeFormat.
 */
function validateTimezone(timezone) {
  try {
    Intl.DateTimeFormat(undefined, { timeZone: timezone });
  } catch {
    console.error(
      `Error: Invalid timezone "${timezone}". Must be a valid IANA timezone.\n` +
      `Examples: Asia/Tokyo, America/New_York, Europe/London, UTC`,
    );
    process.exit(1);
  }
}

/**
 * Generate an 8-character hex schedule ID.
 */
function generateScheduleId() {
  const { randomBytes } = require("crypto");
  return randomBytes(4).toString("hex");
}

/**
 * Build the EventBridge schedule name from userId and scheduleId.
 * Format: openclaw-{userId}-{scheduleId}
 * EventBridge schedule names have a 64-character limit.
 */
function buildScheduleName(userId, scheduleId) {
  const prefix = "openclaw-";
  const suffix = `-${scheduleId}`;
  const maxUserIdLen = 64 - prefix.length - suffix.length;
  const truncatedUserId = userId.length > maxUserIdLen
    ? userId.slice(0, maxUserIdLen)
    : userId;
  return `${prefix}${truncatedUserId}${suffix}`;
}

/**
 * Extract channel and channelTarget from userId.
 * userId format: telegram_12345 -> channel=telegram, channelTarget=12345
 */
function extractChannelInfo(userId) {
  const underscoreIdx = userId.indexOf("_");
  if (underscoreIdx === -1) {
    return { channel: "unknown", channelTarget: userId };
  }
  return {
    channel: userId.substring(0, underscoreIdx),
    channelTarget: userId.substring(underscoreIdx + 1),
  };
}

/**
 * Read the current turn's delivery destination without changing its storage owner.
 */
function resolveScheduleDelivery(userId, { channel, channelTarget } = {}) {
  const identity = JSON.parse(fs.readFileSync("/tmp/current-identity.json", "utf8"));
  if (typeof identity.actorId !== "string" || identity.actorId.replace(/:/g, "_") !== userId) {
    throw new Error("Schedule namespace does not match the AgentCore Runtime owner");
  }
  if (typeof identity.channel !== "string" || !identity.channel ||
      typeof identity.channelActorId !== "string" ||
      !identity.channelActorId.startsWith(`${identity.channel}:`) ||
      !identity.channelActorId.slice(identity.channel.length + 1)) {
    throw new Error("Current channel delivery identity is unavailable");
  }
  if (channel && channel !== identity.channel) {
    throw new Error("Schedule channel must match the current conversation");
  }
  const target = channelTarget === "" ? identity.channelTarget : (channelTarget ?? identity.channelTarget);
  if (typeof target !== "string" || !target) {
    throw new Error("Schedule delivery target is unavailable");
  }
  return {
    actorId: identity.actorId,
    channelActorId: identity.channelActorId,
    channel: identity.channel,
    channelTarget: target,
  };
}

/**
 * Get a DynamoDB Document Client.
 */
function getDynamoClient() {
  const client = new DynamoDBClient({ region: REGION });
  return DynamoDBDocumentClient.from(client);
}

/**
 * Save a cron record to DynamoDB.
 */
async function saveCronRecord(userId, record) {
  const docClient = getDynamoClient();
  await docClient.send(new PutCommand({
    TableName: IDENTITY_TABLE_NAME,
    Item: {
      PK: `USER#${userId}`,
      SK: `CRON#${record.scheduleId}`,
      ...record,
    },
  }));
}

/**
 * Get a cron record from DynamoDB.
 */
async function getCronRecord(userId, scheduleId) {
  const docClient = getDynamoClient();
  const resp = await docClient.send(new GetCommand({
    TableName: IDENTITY_TABLE_NAME,
    Key: {
      PK: `USER#${userId}`,
      SK: `CRON#${scheduleId}`,
    },
  }));
  return resp.Item || null;
}

/**
 * Delete a cron record from DynamoDB.
 */
async function deleteCronRecord(userId, scheduleId) {
  const docClient = getDynamoClient();
  await docClient.send(new DeleteCommand({
    TableName: IDENTITY_TABLE_NAME,
    Key: {
      PK: `USER#${userId}`,
      SK: `CRON#${scheduleId}`,
    },
  }));
}

/**
 * Query all cron records for a user.
 */
async function listCronRecords(userId) {
  const docClient = getDynamoClient();
  const resp = await docClient.send(new QueryCommand({
    TableName: IDENTITY_TABLE_NAME,
    KeyConditionExpression: "PK = :pk AND begins_with(SK, :sk)",
    ExpressionAttributeValues: {
      ":pk": `USER#${userId}`,
      ":sk": "CRON#",
    },
  }));
  return resp.Items || [];
}

/**
 * Update specific fields of a cron record in DynamoDB.
 */
async function updateCronRecord(userId, scheduleId, updates) {
  const docClient = getDynamoClient();
  const expressions = [];
  const attrValues = {};
  const attrNames = {};

  for (const [key, value] of Object.entries(updates)) {
    const placeholder = `:${key}`;
    const nameRef = `#${key}`;
    expressions.push(`${nameRef} = ${placeholder}`);
    attrValues[placeholder] = value;
    attrNames[nameRef] = key;
  }

  if (expressions.length === 0) return;

  await docClient.send(new UpdateCommand({
    TableName: IDENTITY_TABLE_NAME,
    Key: {
      PK: `USER#${userId}`,
      SK: `CRON#${scheduleId}`,
    },
    UpdateExpression: `SET ${expressions.join(", ")}`,
    ExpressionAttributeValues: attrValues,
    ExpressionAttributeNames: attrNames,
  }));
}

module.exports = {
  REGION,
  SCHEDULE_GROUP,
  CRON_LAMBDA_ARN,
  EVENTBRIDGE_ROLE_ARN,
  IDENTITY_TABLE_NAME,
  MIN_INTERVAL_MINUTES,
  MAX_SCHEDULES_PER_USER,
  cronMinuteMinInterval,
  validateUserId,
  validateEnv,
  validateExpression,
  validateTimezone,
  generateScheduleId,
  buildScheduleName,
  extractChannelInfo,
  resolveScheduleDelivery,
  getDynamoClient,
  saveCronRecord,
  getCronRecord,
  deleteCronRecord,
  listCronRecords,
  updateCronRecord,
};
