// Tests for guardrail-blocklist.js and its wiring into agentcore-proxy.js.
// Run: cd bridge && node --test guardrail-blocklist.test.js
//
// Regression: content that triggered an input guardrail intervention must
// not be present untagged in the next Converse request for the same session.

const { describe, it } = require("node:test");
const assert = require("node:assert/strict");
const fs = require("fs");
const path = require("path");

const { scopeGuardrailToLatestUserTurn } = require("./guardrail-scope");
const { createGuardrailBlocklist, BLOCKED_PLACEHOLDER } = require("./guardrail-blocklist");

const u = (...texts) => ({ role: "user", content: texts.map((t) => ({ text: t })) });
const a = (text) => ({ role: "assistant", content: [{ text }] });
const guarded = (t) => ({ guardContent: { text: { text: t } } });

// Same fixture string as the companion scope unit test.
const BLOCKED_TEXT = "My card is 4539 1488 0343 6467";

describe("guardrail-blocklist", () => {
  it("records a blocked turn and strips the same text from history on the next request", () => {
    const bl = createGuardrailBlocklist();
    const sess = "s1";

    const req1 = scopeGuardrailToLatestUserTurn([u(BLOCKED_TEXT)]);
    bl.recordBlockedUserTurn(sess, req1);
    assert.equal(bl.size(sess), 1);

    const history = [u(BLOCKED_TEXT), a("I can't process that request."), u("ok, continue")];
    const redacted = bl.redactBlockedHistory(sess, history);

    const serialised = JSON.stringify(redacted);
    assert.ok(!serialised.includes(BLOCKED_TEXT), "blocked text must not reach Bedrock untagged");
    assert.deepEqual(redacted[0].content, [{ text: BLOCKED_PLACEHOLDER }]);
    assert.deepEqual(redacted[1], history[1]);
    assert.deepEqual(redacted[2], history[2]);

    const scoped = scopeGuardrailToLatestUserTurn(redacted);
    assert.deepEqual(scoped[0].content, [{ text: BLOCKED_PLACEHOLDER }]);
    assert.deepEqual(scoped[2].content, [guarded("ok, continue")]);
    assert.ok(!JSON.stringify(scoped).includes(BLOCKED_TEXT));
  });

  it("matches blocked text robustly against whitespace variants", () => {
    const bl = createGuardrailBlocklist();
    bl.recordBlockedUserTurn("s", [u(BLOCKED_TEXT)]);

    const variant = "  My card is   4539 1488 0343 6467  ";
    const out = bl.redactBlockedHistory("s", [u(variant), u("later")]);
    assert.deepEqual(out[0].content, [{ text: BLOCKED_PLACEHOLDER }]);
    assert.ok(!JSON.stringify(out).includes("4539"));
  });

  it("accepts the tagged guardContent shape when recording after scoping", () => {
    const bl = createGuardrailBlocklist();
    const tagged = [{ role: "user", content: [guarded(BLOCKED_TEXT)] }];
    bl.recordBlockedUserTurn("s", tagged);

    const out = bl.redactBlockedHistory("s", [u(BLOCKED_TEXT)]);
    assert.deepEqual(out[0].content, [{ text: BLOCKED_PLACEHOLDER }]);
  });

  it("isolates sessions: blocking in one does not affect another", () => {
    const bl = createGuardrailBlocklist();
    bl.recordBlockedUserTurn("alice", [u(BLOCKED_TEXT)]);

    const bob = bl.redactBlockedHistory("bob", [u(BLOCKED_TEXT)]);
    assert.deepEqual(bob[0].content, [{ text: BLOCKED_TEXT }]);

    const alice = bl.redactBlockedHistory("alice", [u(BLOCKED_TEXT)]);
    assert.deepEqual(alice[0].content, [{ text: BLOCKED_PLACEHOLDER }]);
  });

  it("does nothing without a session id", () => {
    const bl = createGuardrailBlocklist();
    bl.recordBlockedUserTurn("", [u(BLOCKED_TEXT)]);
    assert.equal(bl.size(""), 0);
    const msgs = [u(BLOCKED_TEXT)];
    assert.equal(bl.redactBlockedHistory("", msgs), msgs);
  });

  it("leaves tool results, images and toolUse blocks untouched", () => {
    const bl = createGuardrailBlocklist();
    bl.recordBlockedUserTurn("s", [u(BLOCKED_TEXT)]);

    const history = [
      u(BLOCKED_TEXT),
      { role: "assistant", content: [{ toolUse: { toolUseId: "t1", name: "exec", input: {} } }] },
      { role: "user", content: [
        { toolResult: { toolUseId: "t1", content: [{ text: "ok" }] } },
        { text: BLOCKED_TEXT },
        { image: { format: "png", source: {} } },
      ] },
    ];
    const out = bl.redactBlockedHistory("s", history);
    assert.deepEqual(out[0].content, [{ text: BLOCKED_PLACEHOLDER }]);
    assert.deepEqual(out[1], history[1]);
    assert.deepEqual(out[2].content[0], history[2].content[0]);
    assert.deepEqual(out[2].content[1], { text: BLOCKED_PLACEHOLDER });
    assert.deepEqual(out[2].content[2], history[2].content[2]);
  });

  it("does not mutate the input array or messages", () => {
    const bl = createGuardrailBlocklist();
    bl.recordBlockedUserTurn("s", [u(BLOCKED_TEXT)]);
    const history = [u(BLOCKED_TEXT), u("hello")];
    const snapshot = JSON.stringify(history);
    bl.redactBlockedHistory("s", history);
    assert.equal(JSON.stringify(history), snapshot);
  });

  it("bounds hashes per session to prevent memory growth", () => {
    const bl = createGuardrailBlocklist();
    for (let i = 0; i < 200; i++) {
      bl.recordBlockedUserTurn("s", [u("blocked payload " + i)]);
    }
    assert.ok(bl.size("s") <= 128);
    const out = bl.redactBlockedHistory("s", [u("blocked payload 199")]);
    assert.deepEqual(out[0].content, [{ text: BLOCKED_PLACEHOLDER }]);
  });
});

describe("agentcore-proxy.js wiring (blocklist)", () => {
  const src = fs.readFileSync(path.join(__dirname, "agentcore-proxy.js"), "utf-8");
  it("requires guardrail-blocklist and threads session id into both invoke paths", () => {
    assert.match(src, /require\("\.\/guardrail-blocklist"\)/);
    assert.match(src, /guardrailBlocklist\.redactBlockedHistory\(sessionId,/);
    const records = src.match(/guardrailBlocklist\.recordBlockedUserTurn\(sessionId,/g) || [];
    assert.ok(records.length >= 2);
  });
  it("still applies scopeGuardrailToLatestUserTurn at every Converse build", () => {
    const builds = src.match(/new Converse(?:Stream)?Command\(params\)/g) || [];
    const scoped = src.match(/messages: guardrailConfig \? scopeGuardrailToLatestUserTurn\(bedrockMessages\) : bedrockMessages/g) || [];
    assert.ok(builds.length >= 2);
    assert.equal(scoped.length, builds.length);
  });
  it("ships the blocklist module in the image", () => {
    const docker = fs.readFileSync(path.join(__dirname, "Dockerfile"), "utf-8");
    assert.match(docker, /COPY guardrail-blocklist\.js \/app\/guardrail-blocklist\.js/);
  });
});
