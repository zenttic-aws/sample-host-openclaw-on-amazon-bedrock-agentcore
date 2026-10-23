#!/usr/bin/env node
/**
 * Shared utilities for api-keys skill.
 */
const REGION = process.env.AWS_REGION;
if (!REGION) {
  console.error("Error: AWS_REGION environment variable is not set.");
  process.exit(1);
}

const VALID_KEY_NAME = /^[a-zA-Z][a-zA-Z0-9_-]{0,63}$/;
const VALID_NAMESPACE = /^(telegram|slack|discord|whatsapp|line)_[a-zA-Z0-9_-]{1,64}$/;

/**
 * Derive the namespace form ("channel_target") from an actorId ("channel:target")
 * or from an already-namespace-shaped identifier. Returns null when the input
 * is not a bound channel actor.
 */
function namespaceFromBinding(value) {
  if (typeof value !== "string" || !value) return null;
  if (VALID_NAMESPACE.test(value)) return value;
  // actorId uses ":" as the first separator (e.g. "telegram:12345")
  const idx = value.indexOf(":");
  if (idx < 0) return null;
  const candidate = value.slice(0, idx) + "_" + value.slice(idx + 1);
  return VALID_NAMESPACE.test(candidate) ? candidate : null;
}

function validateUserId(userId) {
  if (!userId) {
    console.error("Error: user_id argument is required.");
    process.exit(1);
  }
  if (userId === "default-user" || userId === "default_user") {
    console.error("Error: Cannot operate for default-user. User identity was not resolved.");
    process.exit(1);
  }
  if (!VALID_NAMESPACE.test(userId)) {
    console.error(`Error: Invalid user_id "${userId}". Must match channel_identifier format (e.g., telegram_123456).`);
    process.exit(1);
  }
  // Fail closed when the session's bound identity disagrees with the argv
  // user_id. agentcore-contract.js sets USER_ID (actorId, "channel:target")
  // on every container turn; if it is present it is the authoritative owner
  // of the credentials this process will use.
  const boundActor = process.env.USER_ID;
  if (boundActor) {
    const boundNamespace = namespaceFromBinding(boundActor);
    if (!boundNamespace || boundNamespace !== userId) {
      console.error(
        `Error: user_id "${userId}" does not match the session's bound identity ` +
        `(USER_ID="${boundActor}"). Cross-tenant access is not allowed.`,
      );
      process.exit(1);
    }
  }
}

function validateKeyName(keyName) {
  if (!keyName || !VALID_KEY_NAME.test(keyName)) {
    console.error("Error: key_name is required and must be alphanumeric (a-z, 0-9, _, -), starting with a letter, max 64 chars.");
    process.exit(1);
  }
}

// Request timeout for Secrets Manager calls — prevents indefinite hangs
// on VPC endpoint issues. 30s per attempt × 3 retries = ~90s worst case.
const SM_REQUEST_TIMEOUT_MS = 30_000;

module.exports = {
  REGION,
  VALID_KEY_NAME,
  validateUserId,
  validateKeyName,
  SM_REQUEST_TIMEOUT_MS,
};
