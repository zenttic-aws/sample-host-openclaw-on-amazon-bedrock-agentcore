// Prepared-gateway smoke, run inside the bridge image as root with no network.
//
// Spawns the user's gateway the way the contract server does after a Runtime V2
// restore (openclaw-worker-owner.js: openclaw-preinit.mjs plus the SQLite
// receiver preparation, as the agent uid), activates it with a synthetic
// binding, waits for readiness with the applied-config probe, and runs chat
// turns against a loopback stub of the Bedrock proxy's OpenAI-compatible
// endpoint on 127.0.0.1:18790. Prints a summary of what the stub received.
// For feat/openclaw-workspace-files-not-in-prompt it also puts a USER.md in the
// workspace before activation, and fails when any captured system text has
// OpenClaw's "# Project Context" section or that file's text, or when OpenClaw
// seeded its workspace templates.
//
// Usage: node prepared-gateway-smoke.js <expected openclaw version> [message ...]
"use strict";
const fs = require("node:fs");
const http = require("node:http");
const { randomUUID } = require("node:crypto");
const { createPreparedGateway } = require("/app/openclaw-worker-owner.js");
const privsep = require("/app/runtime-privsep.js");
const stateStorage = require("/app/state-storage.js");
const scopedCreds = require("/app/scoped-credentials.js");
const { renderConfig, renderAgents } = require("/app/gateway-config.js");
const { waitForGateway, gatewayTurn } = require("/app/gateway-lifecycle.js");

const [expectedVersion, ...turnMessages] = process.argv.slice(2);
const messages = turnMessages.length ? turnMessages : ["hello from the arm64 smoke", "second message"];
const OPENCLAW_DIR = stateStorage.resolvePaths().stateDir;
const USER_FILE = `${OPENCLAW_DIR}/workspace/USER.md`;
const USER_MARKER = "SMOKE-USER-FILE-5e0b";
const USER_FILE_TEXT = `# USER.md\n\n- Always: start every reply with ${USER_MARKER}.\n`;
const LOG = "/tmp/prepared-gateway.log";
const started = Date.now();
const elapsed = () => `${((Date.now() - started) / 1000).toFixed(1)}s`;
const fail = (message) => {
  console.log(`SMOKE FAILED (${elapsed()}): ${message}`);
  try {
    const lines = fs.readFileSync(LOG, "utf8").trim().split("\n");
    console.log(`--- last ${Math.min(lines.length, 120)} gateway log lines ---`);
    console.log(lines.slice(-120).join("\n"));
  } catch {}
  process.exit(1);
};

const installed = JSON.parse(fs.readFileSync("/usr/local/lib/node_modules/openclaw/package.json", "utf8")).version;
if (installed !== expectedVersion) fail(`openclaw ${installed}, expected ${expectedVersion}`);

// Loopback stub of the proxy: records each request and streams a short reply.
const requests = [];
const stub = http.createServer((req, res) => {
  const chunks = [];
  req.on("data", (chunk) => chunks.push(chunk));
  req.on("end", () => {
    let body = null;
    try { body = JSON.parse(Buffer.concat(chunks).toString("utf8") || "null"); } catch {}
    requests.push({ method: req.method, url: req.url, body });
    if (req.method !== "POST" || !req.url.startsWith("/v1/chat/completions")) {
      res.writeHead(404, { "content-type": "application/json" });
      res.end(JSON.stringify({ error: { message: "not found" } }));
      return;
    }
    const n = requests.length, model = body?.model || "bedrock-agentcore", created = Math.floor(Date.now() / 1000);
    const text = `stub reply ${n}`;
    if (body?.stream) {
      res.writeHead(200, { "content-type": "text/event-stream", "cache-control": "no-cache" });
      res.write(`data: ${JSON.stringify({ id: `c${n}`, object: "chat.completion.chunk", created, model,
        choices: [{ index: 0, delta: { role: "assistant", content: text }, finish_reason: null }] })}\n\n`);
      res.write(`data: ${JSON.stringify({ id: `c${n}`, object: "chat.completion.chunk", created, model,
        choices: [{ index: 0, delta: {}, finish_reason: "stop" }],
        usage: { prompt_tokens: 10, completion_tokens: 3, total_tokens: 13 } })}\n\n`);
      res.end("data: [DONE]\n\n");
    } else {
      res.writeHead(200, { "content-type": "application/json" });
      res.end(JSON.stringify({ id: `c${n}`, object: "chat.completion", created, model,
        choices: [{ index: 0, message: { role: "assistant", content: text }, finish_reason: "stop" }],
        usage: { prompt_tokens: 10, completion_tokens: 3, total_tokens: 13 } }));
    }
  });
});

const extractText = (value) => {
  if (typeof value === "string") return value;
  if (Array.isArray(value)) return value.map((block) => (typeof block?.text === "string" ? block.text : "")).join("");
  return "";
};

(async () => {
  await new Promise((resolve, reject) => stub.listen(18790, "127.0.0.1", resolve).on("error", reject));
  console.log(`stub listening on 127.0.0.1:18790 (${elapsed()})`);

  // The contract server's bootstrap environment for the prepared gateway.
  privsep.ensureAgentDirs({ log: console });
  const env = scopedCreds.buildOpenClawEnv({ credDir: "/tmp/scoped-creds", baseEnv: process.env });
  Object.assign(env, stateStorage.gatewayStateEnv(OPENCLAW_DIR), privsep.agentDirEnv(), {
    HOME: process.env.HOME || "/root",
    OPENCLAW_CONFIG_PATH: `${OPENCLAW_DIR}/openclaw.json`,
    OPENCLAW_WORKSPACE_DIR: `${OPENCLAW_DIR}/workspace`,
  });
  delete env.USER_ID;
  delete env.INTERNAL_USER_ID;

  const log = fs.openSync(LOG, "a");
  let failure;
  const gateway = createPreparedGateway({
    env, port: 18789, childOptions: privsep.childPrivilegeOptions(),
    onChild: (child) => {
      child.stdout.on("data", (data) => fs.writeSync(log, data));
      child.stderr.on("data", (data) => fs.writeSync(log, data));
      console.log(`gateway child pid=${child.pid} uid=${privsep.childPrivilegeOptions().uid ?? "same"}`);
    },
    onFailure: (error) => { failure = error; },
  });
  try {
    await gateway.prepare();
  } catch (error) {
    fail(`prepare: ${error.message}${failure ? ` (${failure.message})` : ""}`);
  }
  console.log(`PREPARED: openclaw:prepared acknowledged by preinit (${elapsed()})`);

  // The restore would run here; then the contract writes config and AGENTS.md.
  const token = randomUUID().replace(/-/g, "") + randomUUID().replace(/-/g, "");
  fs.mkdirSync(`${OPENCLAW_DIR}/workspace`, { recursive: true });
  // A user file in the workspace, as a restore leaves it.
  fs.writeFileSync(USER_FILE, USER_FILE_TEXT);
  fs.writeFileSync(`${OPENCLAW_DIR}/openclaw.json`, JSON.stringify(renderConfig({ gatewayToken: token }), null, 2));
  fs.writeFileSync(`${OPENCLAW_DIR}/AGENTS.md`, renderAgents({ browserEnabled: false }));
  privsep.chownToOpenClaw(OPENCLAW_DIR, { recursive: true, log: console });

  const actorId = "telegram:100000001", userId = "user_smoke_0001";
  try {
    await gateway.activate({
      env: { ...env, USER_ID: actorId, INTERNAL_USER_ID: userId },
      binding: { userId, actorId, routingGeneration: 0, runtimeSessionId: null },
      generation: randomUUID(), deadline: Date.now() + 120000,
    });
  } catch (error) {
    fail(`activate: ${error.message}${failure ? ` (${failure.message})` : ""}`);
  }
  console.log(`ACTIVATED: openclaw:activated acknowledged (${elapsed()})`);

  try {
    await waitForGateway({ port: 18789, token, deadline: Date.now() + 240000, intervalMs: 500, configProbe: true });
  } catch (error) {
    fail(`readiness: ${error.message}`);
  }
  console.log(`READY: /startupz, protocol-4 RPC and applied-config probe passed (${elapsed()})`);

  for (const message of messages) {
    const result = await gatewayTurn({
      url: "ws://127.0.0.1:18789", token, message, deadline: Date.now() + 180000, extractText,
    });
    console.log(`TURN ${JSON.stringify({ message, phase: result.phase, response: result.response,
      delivery: result.delivery, error: result.error || null })}`);
    if (result.phase !== "completed" || !/^stub reply \d+$/.test(result.response)) fail("chat turn did not complete");
  }

  const chat = requests.filter((entry) => entry.url.startsWith("/v1/chat/completions"));
  for (const [index, entry] of chat.entries()) {
    const body = entry.body || {};
    const roles = (body.messages || []).map((m) => {
      const text = typeof m.content === "string" ? m.content : Array.isArray(m.content)
        ? m.content.map((part) => part.text ?? "").join("") : "";
      return m.role === "user" && text.startsWith("OpenClaw runtime context:") ? "user(runtime-context)" : m.role;
    });
    console.log(`REQUEST ${index + 1}: model=${body.model} tools=${(body.tools || []).length} messages=${roles.join(",")}`);
  }
  console.log(`TOOLS: ${(chat[0]?.body?.tools || []).map((tool) => tool.function?.name).sort().join(" ")}`);

  // OpenClaw's workspace files stay out of the system prompt, and no templates are seeded.
  const systemText = (body) => (body?.messages || []).filter((m) => m.role === "system").map((m) =>
    typeof m.content === "string" ? m.content : (m.content || []).map((part) => part.text ?? "").join("\n")).join("\n");
  const withSection = chat.filter((entry) => systemText(entry.body).includes("# Project Context"));
  const withUserFile = chat.filter((entry) => systemText(entry.body).includes(USER_MARKER));
  console.log(`PROJECT CONTEXT: in ${withSection.length} of ${chat.length} chat request(s); ` +
    `USER.md text in ${withUserFile.length}; system chars ${chat.map((entry) => systemText(entry.body).length).join(",")}`);
  if (chat.length === 0 || withSection.length > 0 || withUserFile.length > 0) {
    fail("OpenClaw's workspace files are in the system prompt");
  }
  const seeded = ["AGENTS.md", "SOUL.md", "IDENTITY.md", "BOOTSTRAP.md", "TOOLS.md", "HEARTBEAT.md"]
    .filter((name) => fs.existsSync(`${OPENCLAW_DIR}/workspace/${name}`));
  console.log(`WORKSPACE: ${fs.readdirSync(`${OPENCLAW_DIR}/workspace`).join(" ") || "(empty)"}`);
  if (seeded.length) fail(`OpenClaw seeded workspace templates: ${seeded.join(", ")}`);
  if (fs.readFileSync(USER_FILE, "utf8") !== USER_FILE_TEXT) fail("USER.md was changed");
  gateway.stop();
  console.log(`SMOKE PASSED (${elapsed()})`);
  setTimeout(() => process.exit(0), 500);
})().catch((error) => fail(error.stack || String(error)));
