// SQLite receiver adoption probe, run inside the bridge image as the agent uid with no network.
//
// Prepares the empty SQLite receiver before any user binding (as the bridge preinit does
// through gateway-invariant-prewarm.mjs), arms it with a binding, then starts the OpenClaw
// gateway in this same process and reports whether the gateway's first database open
// adopted the prepared worker ("consumed") or retired it ("retired").
//
// Usage: node sqlite-adoption-probe.mjs
import fs from "node:fs";
import { createRequire } from "node:module";
const require = createRequire(import.meta.url);
const { renderConfig } = require("/app/gateway-config.js");
const PACKAGE = "/usr/local/lib/node_modules/openclaw";
const home = fs.mkdtempSync("/tmp/adoption-home-");
const stateDir = `${home}/.openclaw`;
fs.mkdirSync(`${stateDir}/workspace`, { recursive: true });
const config = renderConfig({ gatewayToken: "a".repeat(64) });
config.gateway.port = 18791;
fs.writeFileSync(`${stateDir}/openclaw.json`, JSON.stringify(config, null, 2));
Object.assign(process.env, {
  HOME: home, OPENCLAW_STATE_DIR: stateDir, OPENCLAW_CONFIG_PATH: `${stateDir}/openclaw.json`,
  OPENCLAW_WORKSPACE_DIR: `${stateDir}/workspace`, OPENCLAW_SKIP_CRON: "1", OPENCLAW_NO_RESPAWN: "1",
  OPENCLAW_AGENTCORE_SQLITE_RECEIVER_PREPARE: "1", OPENCLAW_AGENTCORE_SQLITE_BACKEND_PREPARE: "1",
});
const started = performance.now();
const ms = () => Math.round(performance.now() - started);
// The gateway reroutes console output once it starts, so write probe lines to fd 1 directly
// and end with SIGKILL: the gateway's own exit handling must not keep the probe alive.
const say = (line) => fs.writeSync(1, `${line}\n`);
const finish = (line) => { say(line); process.kill(process.pid, "SIGKILL"); };
const broker = await import(`${PACKAGE}/dist/sqlite-worker-store-CpfrwHqQ.mjs`);
const prepared = await broker.prepareUnboundSqliteReceiver({ timeoutMs: 30000 });
say(`PREPARED ${ms()}ms ${JSON.stringify(prepared)}`);
if (!prepared.prepared || !prepared.backend_definitions_prepared || !prepared.empty) finish("PROBE FAILED: not prepared");
const reservation = globalThis[Symbol.for("openclaw.sqliteWorkerBroker")]?.agentCoreReceiver;
if (!reservation) finish("PROBE FAILED: reservation not found");
process.env.USER_ID = "telegram:100000001";
process.env.INTERNAL_USER_ID = "user_smoke_0001";
const armed = await broker.bindPreparedSqliteReceiver({ generation: "probe", environment: { ...process.env } });
say(`ARMED ${ms()}ms ${JSON.stringify(armed)}`);
const deadline = Date.now() + 120000;
const timer = setInterval(() => {
  const phase = reservation.phase;
  if (phase === "consumed" || phase === "retired" || Date.now() > deadline) {
    clearInterval(timer);
    finish(`ADOPTION ${phase} ${ms()}ms actors=${reservation.slot?.actors?.size ?? 0} thread=${reservation.slot?.worker?.threadId}`);
  }
}, 25);
process.argv = [process.argv[0], `${PACKAGE}/openclaw.mjs`, "gateway", "run", "--port", "18791", "--bind", "loopback"];
await import(`${PACKAGE}/openclaw.mjs`);
