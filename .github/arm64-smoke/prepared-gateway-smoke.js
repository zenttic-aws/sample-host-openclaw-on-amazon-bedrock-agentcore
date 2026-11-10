// Prepared-gateway smoke, run inside the bridge image as root with no network.
//
// Spawns the user's gateway the way the contract server does after a Runtime V2
// restore (openclaw-worker-owner.js: openclaw-preinit.mjs plus the SQLite
// receiver preparation, as the agent uid), activates it with a synthetic
// binding, waits for readiness with the applied-config probe, and runs chat
// turns against a loopback stub of the Bedrock proxy's OpenAI-compatible
// endpoint on 127.0.0.1:18790. Prints a summary of what the stub received.
//
// Usage: node prepared-gateway-smoke.js <expected openclaw version> [message ...]
"use strict";
const fs = require("node:fs");
const http = require("node:http");
const { randomUUID } = require("node:crypto");
// SMOKE_WITHOUT_SQLITE_PREP=1 runs the same flow without the SQLite receiver preparation
// (a copy of openclaw-worker-owner.js minus its two SQLite preparation controls), for timing.
function loadOwner() {
  if (process.env.SMOKE_WITHOUT_SQLITE_PREP !== "1") return require("/app/openclaw-worker-owner.js");
  let source = fs.readFileSync("/app/openclaw-worker-owner.js", "utf8");
  for (const line of ['  OPENCLAW_AGENTCORE_SQLITE_RECEIVER_PREPARE: "1",\n', '  OPENCLAW_AGENTCORE_SQLITE_BACKEND_PREPARE: "1",\n']) {
    if (source.split(line).length !== 2) throw new Error("SQLite preparation control not found in openclaw-worker-owner.js");
    source = source.replace(line, "");
  }
  source = source.replace("${__dirname}/openclaw-preinit.mjs", "/app/openclaw-preinit.mjs");
  fs.writeFileSync("/tmp/openclaw-worker-owner-noprep.js", source);
  return require("/tmp/openclaw-worker-owner-noprep.js");
}
const { createPreparedGateway } = loadOwner();
const privsep = require("/app/runtime-privsep.js");
const stateStorage = require("/app/state-storage.js");
const scopedCreds = require("/app/scoped-credentials.js");
const { renderConfig, renderAgents } = require("/app/gateway-config.js");
const { waitForGateway, gatewayTurn } = require("/app/gateway-lifecycle.js");

const [expectedVersion, ...turnMessages] = process.argv.slice(2);
const messages = turnMessages.length ? turnMessages : ["hello from the arm64 smoke", "second message"];
const OPENCLAW_DIR = stateStorage.resolvePaths().stateDir;
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

// SMOKE_SKILL_DIRS=control|restore: the system prompt's skills catalog after a
// restart from a backup that holds OpenClaw's own skill directories.
//   control: the directories are on local disk, as a restore left them before
//            the bridge stopped restoring them (each probe skill is listed).
//   restore: the same files come from a fake S3 backup and a session-storage
//            mirror through the bridge's own restore code, followed by the
//            activation step removeOpenClawSkillDirs (none is listed).
// In both modes the catalog must still list the image's skills from /skills.
const SKILL_MODE = process.env.SMOKE_SKILL_DIRS || "";
if (SKILL_MODE && !["control", "restore"].includes(SKILL_MODE)) throw new Error(`SMOKE_SKILL_DIRS=${SKILL_MODE}`);
// `backup` probes are in the fake S3 backup and the mirror; the `leftover` one is
// already on local disk before activation (only removeOpenClawSkillDirs acts on it).
const SKILL_PROBES = [
  { rel: "skills/probe-st/SKILL.md", marker: "PROBE-SKILLST-8e21", source: "backup" },
  { rel: "workspace/skills/probe-ws/SKILL.md", marker: "PROBE-SKILLWS-41d7", source: "backup" },
  { rel: "workspace/.agents/skills/probe-ag/SKILL.md", marker: "PROBE-SKILLAG-6d02", source: "backup" },
  { rel: "workspace/skills/probe-lo/SKILL.md", marker: "PROBE-SKILLLO-2b8f", source: "leftover" },
];
const skillMd = ({ rel, marker }) =>
  `---\nname: ${rel.split("/").at(-2)}\ndescription: ${marker} probe skill used by the arm64 smoke.\n---\n\n# probe\n`;
const writeFile = (file, body) => {
  fs.mkdirSync(require("node:path").dirname(file), { recursive: true });
  fs.writeFileSync(file, body);
};

async function placeSkillProbes(mode) {
  const path = require("node:path");
  const stateDir = stateStorage.resolvePaths().stateDir;
  if (mode === "control") {
    for (const probe of SKILL_PROBES) writeFile(path.join(stateDir, probe.rel), skillMd(probe));
  } else {
    const NS = "telegram_100000001";
    const backup = SKILL_PROBES.filter((probe) => probe.source === "backup");
    for (const probe of SKILL_PROBES.filter((p) => p.source === "leftover")) writeFile(path.join(stateDir, probe.rel), skillMd(probe));
    const objects = new Map(backup.map((probe) => [`${NS}/.openclaw/${probe.rel}`, Buffer.from(skillMd(probe))]));
    objects.set(`${NS}/.openclaw/workspace/USER.md`, Buffer.from("# USER.md\n"));
    const sha = (body) => require("node:crypto").createHash("sha256").update(body).digest("hex");
    const fakeS3 = {
      async send(cmd) {
        if (cmd.kind === "list") {
          return { Contents: [...objects].map(([Key, body]) => ({ Key, Size: body.length })), IsTruncated: false };
        }
        const body = objects.get(cmd.input.Key);
        if (!body) throw new Error("NoSuchKey");
        if (cmd.kind === "head") return { ContentLength: body.length, Metadata: { sha256: sha(body) } };
        if (cmd.kind === "get") return { Body: (async function* () { yield body; })(), Metadata: { sha256: sha(body) } };
        throw new Error(`unexpected S3 command ${cmd.kind}`);
      },
    };
    const Module = require("node:module");
    const realLoad = Module._load;
    Module._load = function (request, ...rest) {
      if (request === "@aws-sdk/client-s3") {
        const cmd = (kind) => function (input) { this.kind = kind; this.input = input; };
        return { S3Client: function () { return fakeS3; }, ListObjectsV2Command: cmd("list"),
          GetObjectCommand: cmd("get"), HeadObjectCommand: cmd("head"), PutObjectCommand: cmd("put") };
      }
      return realLoad.call(this, request, ...rest);
    };
    process.env.AWS_REGION = "us-west-2";
    process.env.S3_USER_FILES_BUCKET = "smoke-bucket";
    const mountDir = "/tmp/smoke-mount";
    for (const probe of backup) writeFile(path.join(mountDir, ".openclaw", probe.rel), skillMd(probe));
    writeFile(path.join(mountDir, ".openclaw", "workspace", "MEMORY.md"), "# MEMORY.md\n");
    const quiet = { log() {}, warn: (...a) => console.log("[warn]", ...a), error: (...a) => console.log("[error]", ...a) };
    const mount = stateStorage.setupSessionStorage({ homeDir: process.env.HOME || "/root", mountDir, log: quiet });
    const workspaceSync = require("/app/workspace-sync.js");
    workspaceSync.configureCredentials({ accessKeyId: "AKIAIOSFODNN7EXAMPLE", secretAccessKey: "smoke-not-a-real-secret" });
    const restored = await workspaceSync.restoreWorkspace(NS, { overwrite: false });
    const removed = stateStorage.removeOpenClawSkillDirs(stateDir, { log: quiet });
    console.log(`RESTORE mount=${JSON.stringify(mount.restored)} s3=${JSON.stringify(restored)} removed=${JSON.stringify(removed)}`);
  }
  const onDisk = SKILL_PROBES.filter((probe) => fs.existsSync(path.join(stateDir, probe.rel))).map((probe) => probe.rel);
  console.log(`SKILLS ${mode} on local disk before activation: ${onDisk.length ? onDisk.join(" ") : "none"}`);
}

function checkSkillsCatalog(mode, chat) {
  const last = chat[chat.length - 1]?.body || {};
  const system = (last.messages || []).filter((m) => m.role === "system").map((m) => extractText(m.content)).join("\n");
  const everything = chat.map((entry) => JSON.stringify(entry.body || {})).join("\n");
  const catalog = system.includes("<available_skills>");
  const imageSkills = [...system.matchAll(/<location>\/skills\/([^/<]+)\/SKILL\.md<\/location>/g)].map((m) => m[1]);
  console.log(`SKILLS ${mode} catalog=${catalog} /skills entries listed: ${imageSkills.length ? imageSkills.join(" ") : "none"}`);
  if (!catalog || !imageSkills.length) fail("the skills catalog lists no skill from /skills");
  for (const probe of SKILL_PROBES) {
    const listed = system.includes(probe.marker);
    const anywhere = everything.includes(probe.marker);
    console.log(`SKILLS ${mode} ${probe.rel}: ${listed ? "listed in the system prompt" : anywhere ? "elsewhere in a request" : "absent from every request"}`);
    if (mode === "control" && !listed) fail(`control: ${probe.rel} is not listed, so the check would prove nothing`);
    if (mode === "restore" && anywhere) fail(`restore: ${probe.rel} reached a model request`);
  }
}

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
  if (SKILL_MODE) await placeSkillProbes(SKILL_MODE);
  const token = randomUUID().replace(/-/g, "") + randomUUID().replace(/-/g, "");
  fs.mkdirSync(`${OPENCLAW_DIR}/workspace`, { recursive: true });
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
  if (SKILL_MODE) checkSkillsCatalog(SKILL_MODE, chat);
  const tools = (chat[0]?.body?.tools || []).map((tool) => tool.function?.name).sort();
  console.log(`TOOLS (${tools.length}): ${tools.join(" ")}`);
  if (process.env.EXPECTED_TOOLS && tools.join(" ") !== process.env.EXPECTED_TOOLS.split(/\s+/).sort().join(" ")) {
    fail("offered tool list differs from EXPECTED_TOOLS");
  }
  gateway.stop();
  console.log(`SMOKE PASSED (${elapsed()})`);
  setTimeout(() => process.exit(0), 500);
})().catch((error) => fail(error.stack || String(error)));
