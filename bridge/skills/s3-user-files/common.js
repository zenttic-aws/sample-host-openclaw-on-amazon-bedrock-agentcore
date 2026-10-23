/**
 * Shared utilities for s3-user-files skill.
 */
const path = require("node:path");
const fs = require("node:fs");

const IDENTITY_FILE = "/tmp/current-identity.json";

const BUCKET = process.env.S3_USER_FILES_BUCKET;
const REGION = process.env.AWS_REGION;
if (!REGION) {
  console.error("Error: AWS_REGION environment variable is not set.");
  process.exit(1);
}

/**
 * Sanitize a string for safe use as an S3 key component.
 * Removes path traversal, restricts to safe characters, limits length.
 */
function sanitize(str) {
  // Iteratively remove ".." until stable to prevent "...."->"..".
  let result = str;
  while (result.includes("..")) {
    result = result.replace(/\.\./g, "");
  }
  result = result.replace(/[^a-zA-Z0-9_\-.]/g, "_").slice(0, 256);
  // Reject leading/trailing dots (hidden files, path traversal)
  if (result.startsWith(".") || result.endsWith(".")) {
    throw new Error(
      `Invalid filename: "${result}" — leading/trailing dots not allowed`,
    );
  }
  return result;
}

// Files the Router Lambda stores for the user (Telegram .md/.zip uploads,
// images) live one level down in {user_id}/_uploads/. Accepting exactly this
// one folder lets the agent read the names the router gives it and the names
// list.js prints; any further "/" or ".." is still flattened by sanitize().
const UPLOADS_PREFIX = "_uploads/";

/**
 * Build the S3 key from userId and optional filename.
 * Returns "sanitized_userId/", "sanitized_userId/sanitized_filename", or
 * "sanitized_userId/_uploads/sanitized_name" for router-stored uploads.
 */
function buildKey(userId, filename) {
  const prefix = sanitize(userId);
  if (!filename) return `${prefix}/`;
  if (filename.startsWith(UPLOADS_PREFIX)) {
    const name = sanitize(filename.slice(UPLOADS_PREFIX.length));
    if (!name) throw new Error("Invalid filename: empty name after _uploads/");
    return `${prefix}/${UPLOADS_PREFIX}${name}`;
  }
  return `${prefix}/${sanitize(filename)}`;
}

// download_user_file refuses objects above this size (Telegram uploads are
// at most 20 MB).
const MAX_DOWNLOAD_BYTES = 25 * 1024 * 1024;
const DEFAULT_DOWNLOAD_ROOT = "/tmp/openclaw-uploads";

/**
 * Local path download_user_file writes an object to: the key's base name
 * inside outDir (absolute), or /tmp/openclaw-uploads/<user_id>/ by default.
 */
function downloadPath(userId, key, outDir) {
  const dir = outDir || path.join(DEFAULT_DOWNLOAD_ROOT, sanitize(userId));
  if (!path.isAbsolute(dir)) {
    throw new Error("Output directory must be an absolute path");
  }
  return path.join(dir, path.posix.basename(key));
}

/**
 * Resolve the container's own namespace (actorId with ':' -> '_') from the
 * identity file written by agentcore-contract.js, falling back to the
 * USER_ID / INTERNAL_USER_ID environment variables when the file is absent
 * (same identity the eventbridge-cron skill uses in resolveScheduleDelivery).
 *
 * Returns null when no owner identity can be resolved, in which case the
 * caller must refuse to operate (fail-closed).
 */
function resolveOwnNamespace() {
  try {
    const raw = fs.readFileSync(IDENTITY_FILE, "utf8");
    const identity = JSON.parse(raw);
    if (typeof identity.actorId === "string" && identity.actorId) {
      return identity.actorId.replace(/:/g, "_");
    }
  } catch {
    // fall through to env-var fallback
  }
  const envActor = process.env.USER_ID || process.env.INTERNAL_USER_ID;
  if (typeof envActor === "string" && envActor) {
    return envActor.replace(/:/g, "_");
  }
  return null;
}

/**
 * Validate that userId is present, not the default-user fallback, matches the
 * expected channel_identifier namespace pattern, AND equals the container's
 * own identity. The last check is what prevents an LLM / prompt-injection
 * attacker from choosing another tenant's namespace as the argv argument.
 * Exits the process with an error message if validation fails.
 */
function validateUserId(userId) {
  if (!userId) {
    console.error("Error: user_id argument is required.");
    process.exit(1);
  }
  if (userId === "default-user" || userId === "default_user") {
    console.error(
      "Error: Cannot operate on files for default-user. User identity was not resolved.",
    );
    process.exit(1);
  }
  // Namespace must match channel_identifier pattern (e.g., telegram_123456789, slack_U0XXXXXXXX1).
  // This is a format gate only; it does NOT prove the caller owns the namespace.
  const VALID_NAMESPACE =
    /^(telegram|slack|discord|whatsapp|line)_[a-zA-Z0-9_-]{1,64}$/;
  if (!VALID_NAMESPACE.test(userId)) {
    console.error(
      `Error: Invalid user_id "${userId}". Must match channel_identifier format (e.g., telegram_123456, slack_username).`,
    );
    process.exit(1);
  }
  // Enforce that the argv userId matches the container's own identity. The
  // LLM-supplied argument is attacker-controlled under prompt injection, so
  // without this check a format-valid namespace of any other tenant would be
  // accepted. Mirrors resolveScheduleDelivery in eventbridge-cron/common.js.
  const ownNamespace = resolveOwnNamespace();
  if (!ownNamespace) {
    console.error(
      "Error: Container identity is not available; refusing to operate on user files.",
    );
    process.exit(1);
  }
  if (userId !== ownNamespace) {
    console.error(
      `Error: user_id "${userId}" does not match the container's own namespace "${ownNamespace}". Cross-tenant access is not permitted.`,
    );
    process.exit(1);
  }
}

/**
 * Validate that the S3_USER_FILES_BUCKET env var is set.
 * Exits the process with an error message if missing.
 */
function validateBucket() {
  if (!BUCKET) {
    console.error("Error: S3_USER_FILES_BUCKET environment variable not set.");
    process.exit(1);
  }
}

/**
 * Convert an S3 response body stream to a UTF-8 string.
 */
async function streamToString(stream) {
  const chunks = [];
  for await (const chunk of stream) {
    chunks.push(chunk);
  }
  return Buffer.concat(chunks).toString("utf-8");
}

module.exports = {
  BUCKET,
  REGION,
  sanitize,
  buildKey,
  downloadPath,
  MAX_DOWNLOAD_BYTES,
  validateUserId,
  validateBucket,
  streamToString,
  resolveOwnNamespace,
};
