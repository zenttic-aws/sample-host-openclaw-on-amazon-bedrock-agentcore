/**
 * Per-session sticky redaction of text blocks that Bedrock Guardrails
 * blocked on input (stopReason === "guardrail_intervened").
 *
 * Why this exists. The proxy wraps only the trailing user turn in
 * guardContent (see guardrail-scope.js). Bedrock then assesses only the
 * tagged blocks, so untagged history is never re-assessed. Without a
 * compensating control, a message that the input filter blocked on turn N
 * would be replayed untagged as part of history on turn N+1 and reach the
 * model. OpenClaw's agent transcript is append-only and the whole history
 * is re-sent on every turn, so the proxy itself must strip the blocked
 * block from history before building the Converse request.
 *
 * Design. The proxy keeps an in-memory map from session id to a set of
 * SHA-256 hashes of text blocks it saw get blocked. Hashes rather than the
 * original text so the blocked payload is never retained in memory. On
 * every subsequent Converse call for that session, any text block whose
 * hash is in the set is replaced with a short placeholder before scoping
 * and before the request is sent. The placeholder tells the model that a
 * previous message was blocked by policy without reproducing its content.
 *
 * The set is scoped to a single process (the AgentCore Runtime microVM is
 * per-user, so cross-session leakage is bounded). It is bounded in size per
 * session to limit memory growth, with newest-first eviction. Empty
 * sessionId disables the feature for that request (no shared bucket).
 */

const crypto = require("crypto");

// Placeholder shown in replayed history in place of a previously blocked block.
const BLOCKED_PLACEHOLDER =
  "[redacted: a previous message in this session was blocked by content policy]";

// Hard cap on hashes retained per session to bound memory.
const MAX_HASHES_PER_SESSION = 128;

// Hash a string with SHA-256; returns the hex digest.
function hashText(text) {
  return crypto.createHash("sha256").update(text, "utf8").digest("hex");
}

// Normalise a text block for hashing so trivial reformatting still matches.
function normalise(text) {
  // Trim and collapse runs of whitespace; the goal is to match the block
  // the agent persisted, not a semantically different variant.
  return String(text).trim().replace(/\s+/g, " ");
}

// Create a new blocklist registry (one per proxy process).
function createGuardrailBlocklist() {
  // sessionId -> Set<hash>. A Map preserves insertion order so we can evict
  // the oldest hash when a session exceeds the cap.
  const bySession = new Map();

  function getSet(sessionId) {
    if (!sessionId) return null;
    let set = bySession.get(sessionId);
    if (!set) {
      set = new Set();
      bySession.set(sessionId, set);
    }
    return set;
  }

  // Record every text block of the trailing user turn in bedrockMessages
  // as blocked for sessionId. Called when a Converse response reports
  // stopReason === "guardrail_intervened" on an input assessment, which
  // only triggers on the tagged (trailing) user turn.
  function recordBlockedUserTurn(sessionId, bedrockMessages) {
    const set = getSet(sessionId);
    if (!set || !Array.isArray(bedrockMessages) || bedrockMessages.length === 0) return;

    // Index of the first message of the trailing user turn.
    let start = bedrockMessages.length;
    while (start > 0 && bedrockMessages[start - 1].role === "user") start--;
    if (start === bedrockMessages.length) return;

    for (let i = start; i < bedrockMessages.length; i++) {
      const content = bedrockMessages[i].content || [];
      for (const block of content) {
        // Both tagged (guardContent) and plain {text} shapes can appear here;
        // scopeGuardrailToLatestUserTurn tags before the request, but
        // this function accepts either shape to be robust.
        const text =
          typeof block.text === "string"
            ? block.text
            : block.guardContent?.text?.text;
        if (typeof text !== "string" || text.length === 0) continue;
        const hash = hashText(normalise(text));
        if (set.has(hash)) continue;
        set.add(hash);
        if (set.size > MAX_HASHES_PER_SESSION) {
          // Evict oldest to bound memory. Set iteration order is insertion order.
          const oldest = set.values().next().value;
          if (oldest !== undefined) set.delete(oldest);
        }
      }
    }
  }

  // Return a copy of bedrockMessages where any text block whose normalised
  // hash matches a previously-blocked turn for sessionId is replaced with a
  // short placeholder. Non-text blocks (tool results, images, toolUse) are
  // passed through unchanged. The input is not mutated. If sessionId is
  // empty or nothing has been blocked for that session, the input is
  // returned unchanged.
  function redactBlockedHistory(sessionId, bedrockMessages) {
    const set = sessionId ? bySession.get(sessionId) : null;
    if (!set || set.size === 0 || !Array.isArray(bedrockMessages)) {
      return bedrockMessages;
    }

    let changed = false;
    const out = bedrockMessages.map((msg) => {
      if (!msg || !Array.isArray(msg.content)) return msg;
      let msgChanged = false;
      const newContent = msg.content.map((block) => {
        if (typeof block.text !== "string") return block;
        const hash = hashText(normalise(block.text));
        if (!set.has(hash)) return block;
        msgChanged = true;
        changed = true;
        return { text: BLOCKED_PLACEHOLDER };
      });
      return msgChanged ? { ...msg, content: newContent } : msg;
    });
    return changed ? out : bedrockMessages;
  }

  // Test / diagnostic helper: how many hashes are tracked for a session.
  function size(sessionId) {
    const set = bySession.get(sessionId);
    return set ? set.size : 0;
  }

  // Test helper: drop state for a session (e.g. on session teardown).
  function clearSession(sessionId) {
    bySession.delete(sessionId);
  }

  return {
    recordBlockedUserTurn,
    redactBlockedHistory,
    size,
    clearSession,
    BLOCKED_PLACEHOLDER,
  };
}

module.exports = {
  createGuardrailBlocklist,
  BLOCKED_PLACEHOLDER,
};
