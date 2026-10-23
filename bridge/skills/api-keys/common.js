#!/usr/bin/env node
/**
 * Shared utilities for api-keys skill.
 */
const fs = require("fs");

const REGION = process.env.AWS_REGION;
if (!REGION) {
  console.error("Error: AWS_REGION environment variable is not set.");
  process.exit(1);
}

const VALID_KEY_NAME = /^[a-zA-Z][a-zA-Z0-9_-]{0,63}$/;
const VALID_NAMESPACE = /^(telegram|slack|discord|whatsapp|line)_[a-zA-Z0-9_-]{1,64}$/;
const IDENTITY_FILE = "/tmp/current-identity.json";

/**
 * Derive the container's own namespace from the bound identity.
 *
 * The agent runs in a per-user container; the authenticated namespace is the
 * actorId (channel:target) with the colon rewritten to an underscore, which
 * is the exact format the api-keys CLI accepts as its user_id argument
 * (e.g. "telegram:123456" -> "telegram_123456").
 *
 * Sources, in order:
 *   1. INTERNAL_USER_ID / USER_ID env (set by agentcore-contract.js at bind time)
 *   2. /tmp/current-identity.json (same source eventbridge-cron uses in
 *      resolveScheduleDelivery)
 *
 * Returns null when no bound identity is available (e.g. local dev without a
 * runtime binding, or unit tests); callers treat that as "only shape-check".
 */
function resolveBoundNamespace() {
  const fromEnv = process.env.INTERNAL_USER_ID || process.env.USER_ID;
  if (typeof fromEnv === "string" && fromEnv) {
    return fromEnv.replace(/:/g, "_");
  }
  try {
    const identity = JSON.parse(fs.readFileSync(IDENTITY_FILE, "utf8"));
    if (typeof identity.actorId === "string" && identity.actorId) {
      return identity.actorId.replace(/:/g, "_");
    }
  } catch {
    // No bound identity file available.
  }
  return null;
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
  // Cross-tenant protection: argv-supplied user_id must match the container's
  // own bound identity. Without this check the agent (or indirect prompt
  // injection) can pass another tenant's namespace to read/overwrite/delete
  // their Secrets Manager API keys. The sibling eventbridge-cron skill does
  // the same comparison in resolveScheduleDelivery(). When no identity is
  // bound (unit tests, local dev) we fall back to shape-only validation.
  const bound = resolveBoundNamespace();
  if (bound && bound !== userId) {
    console.error(
      `Error: user_id "${userId}" does not match the container's bound identity "${bound}". ` +
      `Cross-tenant access to api-keys is not permitted.`,
    );
    process.exit(1);
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
