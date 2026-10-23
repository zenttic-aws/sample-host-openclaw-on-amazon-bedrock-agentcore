/**
 * Tests for gateway-mcp.js (mcp.servers.agentcore config) and
 * cognito-token.js (shared per-user token provider).
 * Run: node --test gateway-mcp.test.js
 */
const { describe, it } = require("node:test");
const assert = require("node:assert/strict");

const gw = require("./gateway-mcp");
const { createCognitoTokenProvider } = require("./cognito-token");

const BASE_CONFIG = {
  models: { providers: { agentcore: { baseUrl: "http://127.0.0.1:18790/v1" } } },
  tools: { profile: "full" },
  gateway: { mode: "local", port: 18789 },
};

describe("gateway-mcp.applyGatewayMcp", () => {
  it("leaves the config untouched (same object) when no gateway url is set", () => {
    assert.equal(gw.applyGatewayMcp(BASE_CONFIG, { gatewayUrl: "", token: "t" }), BASE_CONFIG);
    assert.equal(gw.applyGatewayMcp(BASE_CONFIG, {}), BASE_CONFIG);
    assert.equal(JSON.stringify(gw.applyGatewayMcp(BASE_CONFIG, { gatewayUrl: undefined })), JSON.stringify(BASE_CONFIG));
    assert.equal("mcp" in BASE_CONFIG, false);
  });

  it("adds mcp.servers.agentcore as a streamable-http server with a bearer header", () => {
    const url = "https://abc123.gateway.bedrock-agentcore.us-west-2.amazonaws.com/mcp";
    const out = gw.applyGatewayMcp(BASE_CONFIG, { gatewayUrl: url, token: "eyJ.id.token" });
    assert.notEqual(out, BASE_CONFIG);
    assert.equal("mcp" in BASE_CONFIG, false, "input not mutated");
    assert.deepEqual(out.mcp.servers.agentcore, {
      url,
      transport: "streamable-http",
      headers: { Authorization: "Bearer eyJ.id.token" },
      requestTimeoutMs: 30000,
      connectionTimeoutMs: 10000,
      supportsParallelToolCalls: true,
    });
    assert.deepEqual(out.models, BASE_CONFIG.models);
    assert.deepEqual(out.tools, BASE_CONFIG.tools);
  });

  it("keeps other mcp servers and requires a token", () => {
    const cfg = { ...BASE_CONFIG, mcp: { servers: { docs: { command: "uvx" } } } };
    const out = gw.applyGatewayMcp(cfg, { gatewayUrl: "https://x/mcp", token: "t" });
    assert.deepEqual(Object.keys(out.mcp.servers).sort(), ["agentcore", "docs"]);
    assert.throws(() => gw.applyGatewayMcp(cfg, { gatewayUrl: "https://x/mcp", token: null }), /token is required/);
  });

  it("isEnabled reflects a non-blank AGENTCORE_GATEWAY_URL only", () => {
    assert.equal(gw.isEnabled({}), false);
    assert.equal(gw.isEnabled({ AGENTCORE_GATEWAY_URL: "  " }), false);
    assert.equal(gw.isEnabled({ AGENTCORE_GATEWAY_URL: "https://x/mcp" }), true);
  });
});

describe("cognito-token.createCognitoTokenProvider", () => {
  const commands = {};
  for (const n of [
    "CognitoIdentityProviderClient",
    "AdminGetUserCommand",
    "AdminCreateUserCommand",
    "AdminSetUserPasswordCommand",
    "AdminInitiateAuthCommand",
  ]) {
    commands[n] = class {
      constructor(input) { this.input = input; }
    };
    Object.defineProperty(commands[n], "name", { value: n });
  }
  const secretsCommands = {};
  for (const n of ["SecretsManagerClient", "GetSecretValueCommand", "CreateSecretCommand", "PutSecretValueCommand"]) {
    secretsCommands[n] = class {
      constructor(input) { this.input = input; }
    };
    Object.defineProperty(secretsCommands[n], "name", { value: n });
  }

  function makeSecretsStore(initial = {}) {
    const store = new Map(Object.entries(initial));
    const sent = [];
    const client = {
      async send(cmd) {
        sent.push(cmd);
        const name = cmd.constructor.name;
        if (name === "GetSecretValueCommand") {
          const value = store.get(cmd.input.SecretId);
          if (value === undefined) {
            throw Object.assign(new Error("not found"), { name: "ResourceNotFoundException" });
          }
          return { SecretString: value };
        }
        if (name === "CreateSecretCommand") {
          if (store.has(cmd.input.Name)) {
            throw Object.assign(new Error("exists"), { name: "ResourceExistsException" });
          }
          store.set(cmd.input.Name, cmd.input.SecretString);
          return {};
        }
        if (name === "PutSecretValueCommand") {
          store.set(cmd.input.SecretId, cmd.input.SecretString);
          return {};
        }
        return {};
      },
    };
    return { client, store, sent };
  }

  const cfg = {
    userPoolId: "us-west-2_POOL",
    clientId: "client",
    region: "us-west-2",
    commands,
    secretsCommands,
  };

  it("returns null when not configured and caches tokens until 60 s before expiry", async () => {
    const sm = makeSecretsStore();
    assert.equal(
      await createCognitoTokenProvider({ ...cfg, clientId: "", secretsClient: sm.client }).getIdToken("a"),
      null,
    );

    const sentCognito = [];
    const client = {
      send: async (cmd) => {
        sentCognito.push(cmd.constructor.name);
        if (cmd.constructor.name === "AdminGetUserCommand") return {};
        if (cmd.constructor.name === "AdminSetUserPasswordCommand") return {};
        if (cmd.constructor.name === "AdminInitiateAuthCommand") {
          return {
            AuthenticationResult: {
              IdToken: `tok${sentCognito.length}`,
              AccessToken: `acc${sentCognito.length}`,
              ExpiresIn: 3600,
            },
          };
        }
        return {};
      },
    };
    const provider = createCognitoTokenProvider({ ...cfg, client, secretsClient: sm.client, log: () => {} });
    const first = await provider.getIdToken("telegram:1");
    assert.match(first.token, /^tok/);
    assert.ok(first.expiresAt > Date.now() + 3500 * 1000);
    const second = await provider.getIdToken("telegram:1");
    assert.equal(second, first, "cached");
    const access = await provider.getAccessToken("telegram:1");
    assert.match(access.token, /^acc/);
    assert.equal(access.expiresAt, first.expiresAt);
    assert.equal(
      sentCognito.filter((n) => n === "AdminInitiateAuthCommand").length,
      1,
      "no extra auth for the access token",
    );
    const forced = await provider.getIdToken("telegram:1", { force: true });
    assert.notEqual(forced.token, first.token, "force bypasses the cache");
    assert.equal(
      sentCognito.filter((n) => n === "AdminInitiateAuthCommand").length,
      2,
    );
    // After the first provisioning the per-user secret must exist.
    assert.equal(sm.store.get("openclaw/user/telegram_1/cognito")?.length > 0, true);
  });

  it("getAccessToken refuses to hand out an empty bearer", async () => {
    const sm = makeSecretsStore({ "openclaw/user/telegram_1/cognito": "stored-pw" });
    const client = {
      send: async (cmd) => {
        if (cmd.constructor.name === "AdminInitiateAuthCommand") {
          return { AuthenticationResult: { IdToken: "t", ExpiresIn: 3600 } };
        }
        return {};
      },
    };
    const provider = createCognitoTokenProvider({ ...cfg, client, secretsClient: sm.client, log: () => {} });
    await assert.rejects(provider.getAccessToken("telegram:1"), /no AccessToken/);
    const sm2 = makeSecretsStore();
    assert.equal(
      await createCognitoTokenProvider({ ...cfg, clientId: "", secretsClient: sm2.client }).getAccessToken("a"),
      null,
    );
  });

  it("provisions a missing user with a per-user random password stored in Secrets Manager", async () => {
    const sm = makeSecretsStore();
    const sent = [];
    const client = {
      send: async (cmd) => {
        sent.push(cmd);
        const n = cmd.constructor.name;
        if (n === "AdminGetUserCommand") {
          throw Object.assign(new Error("nf"), { name: "UserNotFoundException" });
        }
        if (n === "AdminInitiateAuthCommand") {
          return { AuthenticationResult: { IdToken: "t", ExpiresIn: 3600 } };
        }
        return {};
      },
    };
    const provider = createCognitoTokenProvider({ ...cfg, client, secretsClient: sm.client, log: () => {} });
    await provider.getIdToken("slack:U1");
    const names = sent.map((c) => c.constructor.name);
    assert.deepEqual(names, [
      "AdminGetUserCommand",
      "AdminCreateUserCommand",
      "AdminSetUserPasswordCommand",
      "AdminInitiateAuthCommand",
    ]);
    const setPw = sent[2].input;
    assert.equal(setPw.Permanent, true);
    const stored = sm.store.get("openclaw/user/slack_U1/cognito");
    assert.equal(typeof stored, "string");
    assert.equal(stored.length > 16, true, "random password should be long");
    assert.equal(setPw.Password, stored, "stored password must match the one set on Cognito");
    assert.equal(sent[3].input.AuthFlow, "ADMIN_USER_PASSWORD_AUTH");
    assert.equal(sent[3].input.AuthParameters.PASSWORD, stored);
  });

  it("does NOT derive the password from a shared key: two users get different passwords", async () => {
    const sm = makeSecretsStore();
    const client = {
      send: async (cmd) => {
        const n = cmd.constructor.name;
        if (n === "AdminGetUserCommand") {
          throw Object.assign(new Error("nf"), { name: "UserNotFoundException" });
        }
        if (n === "AdminInitiateAuthCommand") {
          return { AuthenticationResult: { IdToken: "t", ExpiresIn: 3600 } };
        }
        return {};
      },
    };
    const provider = createCognitoTokenProvider({ ...cfg, client, secretsClient: sm.client, log: () => {} });
    await provider.getIdToken("telegram:a");
    await provider.getIdToken("telegram:b");
    const pwA = sm.store.get("openclaw/user/telegram_a/cognito");
    const pwB = sm.store.get("openclaw/user/telegram_b/cognito");
    assert.equal(typeof pwA, "string");
    assert.equal(typeof pwB, "string");
    assert.notEqual(pwA, pwB, "two users must have independently generated passwords");
  });

  it("rotates the password when a Cognito user exists but no stored secret", async () => {
    // Simulates a legacy user from the old HMAC-derived scheme.
    const sm = makeSecretsStore();
    const sent = [];
    const client = {
      send: async (cmd) => {
        sent.push(cmd.constructor.name);
        const n = cmd.constructor.name;
        if (n === "AdminGetUserCommand") return {}; // user exists
        if (n === "AdminInitiateAuthCommand") {
          return { AuthenticationResult: { IdToken: "t", ExpiresIn: 3600 } };
        }
        return {};
      },
    };
    const provider = createCognitoTokenProvider({ ...cfg, client, secretsClient: sm.client, log: () => {} });
    await provider.getIdToken("telegram:legacy");
    assert.deepEqual(sent, [
      "AdminGetUserCommand",
      "AdminSetUserPasswordCommand",
      "AdminInitiateAuthCommand",
    ]);
    assert.equal(typeof sm.store.get("openclaw/user/telegram_legacy/cognito"), "string");
  });
});
