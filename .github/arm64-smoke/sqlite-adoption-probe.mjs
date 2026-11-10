// SQLite receiver adoption probe, run inside the bridge image as the agent uid with no network.
//
// Prepares the empty SQLite receiver before any user binding (as the bridge preinit does
// through gateway-invariant-prewarm.mjs), arms it with a binding, then starts the OpenClaw
// gateway in this same process and records whether the gateway's first database open
// adopted the prepared worker ("consumed") or retired it ("retired").
//
// Results go to /probe/result.txt (a host bind mount): the gateway reroutes console output
// and handles process exit once it starts, so the workflow reads the file and removes the
// container itself.
//
// Usage: node sqlite-adoption-probe.mjs
import fs from "node:fs";
import { createRequire } from "node:module";
const require = createRequire(import.meta.url);
const { renderConfig } = require("/app/gateway-config.js");
const PACKAGE = "/usr/local/lib/node_modules/openclaw";
const RESULT = "/probe/result.txt";
const started = performance.now();
const ms = () => Math.round(performance.now() - started);
const out = (line) => fs.appendFileSync(RESULT, `${line}\n`);
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
const broker = await import(`${PACKAGE}/dist/sqlite-worker-store-CpfrwHqQ.mjs`);
const prepared = await broker.prepareUnboundSqliteReceiver({ timeoutMs: 30000 });
out(`PREPARED ${ms()}ms ${JSON.stringify(prepared)}`);
const reservation = globalThis[Symbol.for("openclaw.sqliteWorkerBroker")]?.agentCoreReceiver;
if (!reservation || !prepared.prepared || !prepared.backend_definitions_prepared || !prepared.empty) {
  out("ADOPTION probe-failed: not prepared");
} else {
  // Record the claim the moment the gateway's first open makes it.
  const claim = reservation.claim.bind(reservation);
  reservation.claim = async (...args) => {
    out(`CLAIM start ${ms()}ms`);
    try {
      const slot = await claim(...args);
      out(`ADOPTION ${slot ? "consumed" : "retired"} ${ms()}ms phase=${reservation.phase} actors=${slot?.actors?.size ?? 0} thread=${slot?.worker?.threadId ?? "none"}`);
      return slot;
    } catch (error) {
      out(`ADOPTION failed ${ms()}ms phase=${reservation.phase} ${error?.message}`);
      throw error;
    }
  };
  process.env.USER_ID = "telegram:100000001";
  process.env.INTERNAL_USER_ID = "user_smoke_0001";
  const armed = await broker.bindPreparedSqliteReceiver({ generation: "probe", environment: { ...process.env } });
  out(`ARMED ${ms()}ms ${JSON.stringify(armed)}`);
  const watchdog = setInterval(() => out(`TICK ${ms()}ms phase=${reservation.phase}`), 10000);
  watchdog.unref();
}
process.argv = [process.argv[0], `${PACKAGE}/openclaw.mjs`, "gateway", "run", "--port", "18791", "--bind", "loopback"];
out(`GATEWAY import ${ms()}ms`);
await import(`${PACKAGE}/openclaw.mjs`);
out(`GATEWAY import returned ${ms()}ms`);
