/**
 * Forward late sub-agent announce finals to the user (issue #148, option B).
 *
 * When a sub-agent finishes while its requester session is idle, openclaw
 * 2026.9.5 starts an "announce" run in that session through the gateway's
 * `agent` method. Its run id is the announce idempotency key,
 * `announce:v1:<child session key>:<child run id>` (upstream
 * src/agents/announce-idempotency.ts, isAnnounceRunId). The container has no
 * channels, so that run's final only lands in the transcript and the user
 * sees it on their next turn.
 *
 * The relay watches chat finals, keeps only announce runs in the main
 * session that no bridge turn returned, and hands their answer to `deliver`,
 * which uses the bridge's existing Telegram send path. `message` stays
 * denied (#122); nothing here lets the agent pick a destination.
 *
 * Ordering and dedupe:
 * - A final that arrives while a turn is active waits until every active turn
 *   has ended plus `settleMs`, so it never goes out ahead of the main reply.
 *   If the turn returned that run itself (a sessions_yield successor), it is
 *   dropped.
 * - Each announce run id is handled at most once per container.
 * - The destination is the route that was active when the sub-agent that
 *   produced this announce was first observed (its "originating" turn),
 *   NOT the latest turn's route. The announce runId embeds the sub-agent
 *   sessionKey (`announce:v1:<sub-agent sessionKey>:<child run id>`); the
 *   relay records that sessionKey -> route when it first sees any event for
 *   the sub-agent session, so a later turn in a different conversation can
 *   never redirect the delivery. deliverLateAnnounce performs an ownership
 *   check on the full triple (channel, channelActorId, channelTarget).
 */
const { isSubagentSessionKey } = require("./chat-run-filter");

const ANNOUNCE_RUN_PREFIX = "announce:";
const ANNOUNCE_RUN_ID_PREFIX = "announce:v1:";
const SILENT_REPLIES = new Set(["NO_REPLY", "HEARTBEAT_OK"]);
const DEFAULT_SETTLE_MS = 5000;
const DEFAULT_MAX_REMEMBERED = 500;

/** Mirrors upstream isAnnounceRunId (announce-idempotency.ts). */
function isAnnounceRunId(runId) {
  return typeof runId === "string" && runId.startsWith(ANNOUNCE_RUN_PREFIX);
}

/**
 * Extract the sub-agent sessionKey embedded in an announce run id. Mirrors
 * upstream buildAnnounceIdempotencyKey (announce-idempotency.ts):
 * `announce:v1:<sub-agent sessionKey>:<child run id>`. Returns null if the
 * run id does not match that shape.
 */
function parseAnnounceSubagentSessionKey(runId) {
  if (typeof runId !== "string" || !runId.startsWith(ANNOUNCE_RUN_ID_PREFIX)) return null;
  const rest = runId.slice(ANNOUNCE_RUN_ID_PREFIX.length);
  const lastColon = rest.lastIndexOf(":");
  if (lastColon <= 0 || lastColon === rest.length - 1) return null;
  const sessionKey = rest.slice(0, lastColon);
  return sessionKey || null;
}

/** openclaw's silent reply tokens mean the run chose not to say anything. */
function isSilentReply(text) {
  const trimmed = typeof text === "string" ? text.trim() : "";
  return !trimmed || SILENT_REPLIES.has(trimmed);
}

/** A Set that forgets its oldest entries past `limit`. */
function boundedSet(limit) {
  const items = new Set();
  return {
    has: (value) => items.has(value),
    add: (value) => {
      items.delete(value);
      items.add(value);
      while (items.size > limit) items.delete(items.values().next().value);
    },
  };
}

/** A Map that forgets its oldest entries past `limit`. */
function boundedMap(limit) {
  const items = new Map();
  return {
    has: (key) => items.has(key),
    get: (key) => items.get(key),
    set: (key, value) => {
      items.delete(key);
      items.set(key, value);
      while (items.size > limit) items.delete(items.keys().next().value);
    },
  };
}

/**
 * True if two routes point at the same delivery triple (channel +
 * channelActorId + channelTarget). actorId is deliberately not part of this
 * comparison: the lifecycle binding already forces a single actorId, so it
 * does not distinguish conversations within one bound user.
 */
function sameConversation(a, b) {
  if (!a || !b) return false;
  return a.channel === b.channel &&
    (a.channelActorId ?? null) === (b.channelActorId ?? null) &&
    (a.channelTarget ?? null) === (b.channelTarget ?? null);
}

function bufferText(payload) {
  const content = payload?.message?.content;
  if (typeof content === "string") return content;
  if (!Array.isArray(content)) return "";
  return content.filter((block) => block?.type === "text" && typeof block.text === "string")
    .map((block) => block.text).join("");
}

/**
 * @param {object} options
 * @param {(entry: {runId: string, sessionKey: string, buffer: string}) => Promise<string|null>} options.fetchAnswer
 * @param {(text: string, route: object, meta: {runId: string}) => Promise<unknown>} options.deliver
 */
function createLateAnnounceRelay({
  fetchAnswer, deliver, log = console, settleMs = DEFAULT_SETTLE_MS, maxRemembered = DEFAULT_MAX_REMEMBERED,
}) {
  const seen = boundedSet(maxRemembered); // announce runs already queued or handled
  const claimed = boundedSet(maxRemembered); // runs some bridge turn returned
  // Sub-agent sessionKey -> route of the turn that was active when we first
  // observed any event for that sub-agent session. The announce runId embeds
  // that sessionKey, so we can resolve the originating turn's route even if
  // a later turn (in a different conversation) overwrites the current route.
  const subagentRoutes = boundedMap(maxRemembered);
  const pending = [];
  const activeTurns = new Set();
  let route = null;
  let closed = false;
  let timer = null;
  let draining = null;
  let idleWaiters = [];

  const settleIdle = () => {
    if (pending.length || timer || draining) return;
    const waiters = idleWaiters;
    idleWaiters = [];
    for (const resolve of waiters) resolve();
  };

  const drain = async () => {
    while (pending.length && !closed && activeTurns.size === 0) {
      const entry = pending.shift();
      if (claimed.has(entry.runId)) continue;
      // Deliver to the route that was active when the sub-agent that produced
      // this announce was first observed, NOT the latest turn's route. This
      // prevents a later turn in a different conversation from redirecting a
      // private sub-agent answer into a group chat (CWE-359).
      const target = entry.originatingRoute;
      if (!target) {
        log?.warn?.(
          "[late-announce] No originating route for announce run; not delivered (runId: %s)",
          entry.runId,
        );
        continue;
      }
      try {
        const text = await fetchAnswer(entry);
        if (closed || claimed.has(entry.runId)) continue;
        if (isSilentReply(text)) {
          log?.log?.("[late-announce] Announce run ended without text to deliver");
          continue;
        }
        await deliver(text.trim(), target, { runId: entry.runId });
        log?.log?.("[late-announce] Delivered a late sub-agent announce; chars:", text.trim().length);
      } catch (error) {
        log?.warn?.("[late-announce] Late announce delivery failed:", error?.message || "unknown error");
      }
    }
  };

  const schedule = () => {
    if (closed || timer || draining || activeTurns.size || !pending.length) return settleIdle();
    timer = setTimeout(() => {
      timer = null;
      if (closed || activeTurns.size) return settleIdle();
      draining = drain().finally(() => {
        draining = null;
        schedule();
      });
    }, settleMs);
    timer.unref?.();
  };

  /**
   * Mark a bridge turn active. `claim(runId)` records a run the turn returns;
   * `end()` lets held finals go out. `route` is the turn's validated channel.
   */
  const beginTurn = (turnRoute) => {
    const token = {};
    activeTurns.add(token);
    if (turnRoute && typeof turnRoute === "object") route = Object.freeze({ ...turnRoute });
    if (timer) {
      clearTimeout(timer);
      timer = null;
    }
    return {
      claim: (runId) => { if (typeof runId === "string" && runId) claimed.add(runId); },
      end: () => {
        if (!activeTurns.delete(token)) return;
        schedule();
      },
    };
  };

  const onChatEvent = (payload) => {
    if (closed || !payload || typeof payload !== "object") return;
    const { runId, sessionKey } = payload;
    const subagent = (typeof sessionKey === "string" && isSubagentSessionKey(sessionKey)) ||
      Boolean(payload.spawnedBy);
    // Record the originating turn's route for every sub-agent session we see
    // events for. First sighting wins so a later turn's route cannot overwrite
    // the mapping. `route` is captured only when a turn is active, i.e. a
    // route that the contract's assertBinding has already validated for this
    // user binding. We cannot use payload.spawnedBy as a map key because it is
    // the parent sessionKey (main), not the sub-agent's.
    if (subagent && typeof sessionKey === "string" && sessionKey && route &&
        activeTurns.size > 0 && !subagentRoutes.has(sessionKey)) {
      subagentRoutes.set(sessionKey, route);
    }
    if (payload.state !== "final" || payload.yielded === true) return;
    if (!isAnnounceRunId(runId) || typeof sessionKey !== "string" || !sessionKey) return;
    if (subagent) return;
    if (seen.has(runId) || claimed.has(runId)) return;
    seen.add(runId);
    // Resolve the sub-agent sessionKey embedded in the announce run id and
    // look up the originating turn's route. If we never saw a sub-agent event
    // (e.g. the sub-agent predates this activation or events were dropped),
    // originatingRoute is null and the drain will skip delivery rather than
    // guess the destination.
    const subagentKey = parseAnnounceSubagentSessionKey(runId);
    const originatingRoute = subagentKey ? (subagentRoutes.get(subagentKey) ?? null) : null;
    pending.push({ runId, sessionKey, buffer: bufferText(payload), originatingRoute });
    schedule();
  };

  /** Resolves when nothing is queued or being sent (for tests and shutdown). */
  const idle = () => new Promise((resolve) => {
    idleWaiters.push(resolve);
    settleIdle();
  });

  const close = () => {
    closed = true;
    pending.length = 0;
    if (timer) {
      clearTimeout(timer);
      timer = null;
    }
    settleIdle();
  };

  return { beginTurn, onChatEvent, idle, close };
}

module.exports = {
  createLateAnnounceRelay,
  isAnnounceRunId,
  parseAnnounceSubagentSessionKey,
  isSilentReply,
  sameConversation,
  ANNOUNCE_RUN_PREFIX,
  ANNOUNCE_RUN_ID_PREFIX,
};
