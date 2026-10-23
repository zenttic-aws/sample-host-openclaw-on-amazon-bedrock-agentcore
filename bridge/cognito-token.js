/**
 * Per-user Cognito token minting, shared by the Bedrock proxy
 * (agentcore-proxy.js) and the contract server (agentcore-contract.js, which
 * uses the ACCESS token as the bearer for the AgentCore Gateway MCP server
 * entry in openclaw.json).
 *
 * One Cognito user per actorId ("telegram:123"). The password is generated
 * once with crypto.randomBytes and persisted in Secrets Manager at
 * `openclaw/user/<namespace>/cognito` (one secret per user). The password is
 * NEVER derived from a shared key: a previous design derived it as
 * HMAC-SHA256(COGNITO_PASSWORD_SECRET, actorId), which meant any process that
 * learned the single HMAC key could compute every user's password and mint a
 * token for an arbitrary actorId. Per-user secrets break that cross-user
 * token minting path.
 *
 * Access to the per-user secret is further restricted by the agent's STS
 * session policy, which only permits secretsmanager:GetSecretValue on
 * `openclaw/user/<its-own-namespace>/*`, so even reading the proxy's
 * credentials from a sibling process grants nothing beyond the bound user's
 * own secret.
 */
"use strict";

const crypto = require("crypto");

function actorToNamespace(actorId) {
  return String(actorId || "").replace(/:/g, "_");
}

function defaultSecretId(actorId) {
  return "openclaw/user/" + actorToNamespace(actorId) + "/cognito";
}

function generateRandomPassword() {
  // 24 random bytes -> 32 base64url chars. Appended "!1" guarantees the
  // Cognito pool's "symbols" and "numbers" character classes even if its
  // password policy is strict.
  return crypto.randomBytes(24).toString("base64url") + "!1";
}

function createCognitoTokenProvider(config) {
  const {
    userPoolId,
    clientId,
    region,
    client, // injectable CognitoIdentityProviderClient (tests)
    commands, // injectable Cognito command classes (tests)
    secretsClient, // injectable SecretsManagerClient (tests)
    secretsCommands, // injectable Secrets Manager command classes (tests)
    secretId = defaultSecretId,
    generatePassword = generateRandomPassword,
    log = console.log,
  } = config;

  let _client = client || null;
  let _commands = commands || null;
  let _secretsClient = secretsClient || null;
  let _secretsCommands = secretsCommands || null;

  function sdk() {
    if (!_commands) _commands = require("@aws-sdk/client-cognito-identity-provider");
    return _commands;
  }
  function smSdk() {
    if (!_secretsCommands) _secretsCommands = require("@aws-sdk/client-secrets-manager");
    return _secretsCommands;
  }

  const tokenCache = new Map();

  function isConfigured() {
    return Boolean(userPoolId && clientId);
  }

  function getClient() {
    if (!_client) {
      _client = new (sdk().CognitoIdentityProviderClient)({ region });
    }
    return _client;
  }

  function getSecretsClient() {
    if (!_secretsClient) {
      _secretsClient = new (smSdk().SecretsManagerClient)({ region });
    }
    return _secretsClient;
  }

  async function fetchStoredPassword(actorId) {
    const { GetSecretValueCommand } = smSdk();
    try {
      const resp = await getSecretsClient().send(
        new GetSecretValueCommand({ SecretId: secretId(actorId) }),
      );
      return resp.SecretString || null;
    } catch (err) {
      if (err && (err.name === "ResourceNotFoundException" || err.$metadata?.httpStatusCode === 404)) {
        return null;
      }
      throw err;
    }
  }

  async function storePassword(actorId, password) {
    const { CreateSecretCommand, PutSecretValueCommand } = smSdk();
    const sId = secretId(actorId);
    try {
      await getSecretsClient().send(
        new CreateSecretCommand({ Name: sId, SecretString: password }),
      );
    } catch (err) {
      if (err && err.name === "ResourceExistsException") {
        await getSecretsClient().send(
          new PutSecretValueCommand({ SecretId: sId, SecretString: password }),
        );
      } else {
        throw err;
      }
    }
  }

  async function ensureUser(actorId) {
    const {
      AdminGetUserCommand,
      AdminCreateUserCommand,
      AdminSetUserPasswordCommand,
    } = sdk();
    const c = getClient();
    let userExists = true;
    try {
      await c.send(new AdminGetUserCommand({ UserPoolId: userPoolId, Username: actorId }));
    } catch (err) {
      if (err.name !== "UserNotFoundException") throw err;
      userExists = false;
    }
    if (userExists) {
      const stored = await fetchStoredPassword(actorId);
      if (stored) return stored;
      // User exists but no per-user secret (legacy or externally created) —
      // rotate to a fresh random password and persist it.
      const password = generatePassword();
      await c.send(
        new AdminSetUserPasswordCommand({
          UserPoolId: userPoolId,
          Username: actorId,
          Password: password,
          Permanent: true,
        }),
      );
      await storePassword(actorId, password);
      log("[cognito] user password rotated: " + actorId);
      return password;
    }
    const password = generatePassword();
    await c.send(
      new AdminCreateUserCommand({
        UserPoolId: userPoolId,
        Username: actorId,
        MessageAction: "SUPPRESS",
        TemporaryPassword: password,
      }),
    );
    await c.send(
      new AdminSetUserPasswordCommand({
        UserPoolId: userPoolId,
        Username: actorId,
        Password: password,
        Permanent: true,
      }),
    );
    await storePassword(actorId, password);
    log("[cognito] user provisioned: " + actorId);
    return password;
  }

  async function authenticate(actorId, { force = false } = {}) {
    if (!isConfigured()) return null;
    const cached = tokenCache.get(actorId);
    if (!force && cached && cached.expiresAt > Date.now()) return cached;

    const password = await ensureUser(actorId);
    const { AdminInitiateAuthCommand } = sdk();
    const response = await getClient().send(
      new AdminInitiateAuthCommand({
        UserPoolId: userPoolId,
        ClientId: clientId,
        AuthFlow: "ADMIN_USER_PASSWORD_AUTH",
        AuthParameters: { USERNAME: actorId, PASSWORD: password },
      }),
    );
    const result = response.AuthenticationResult;
    const expiresIn = result.ExpiresIn || 3600;
    const expiresAt = Date.now() + (expiresIn - 60) * 1000;
    const entry = {
      expiresAt,
      id: { token: result.IdToken, expiresAt, expiresIn },
      access: { token: result.AccessToken, expiresAt, expiresIn },
    };
    tokenCache.set(actorId, entry);
    log("[cognito] token acquired for " + actorId + " (expires in " + expiresIn + "s)");
    return entry;
  }

  async function getIdToken(actorId, opts) {
    const entry = await authenticate(actorId, opts);
    return entry ? entry.id : null;
  }

  async function getAccessToken(actorId, opts) {
    const entry = await authenticate(actorId, opts);
    if (!entry) return null;
    if (!entry.access.token) throw new Error("Cognito returned no AccessToken");
    return entry.access;
  }

  return {
    isConfigured,
    ensureUser,
    getIdToken,
    getAccessToken,
    _cache: tokenCache,
    _secretId: secretId,
  };
}

module.exports = { createCognitoTokenProvider, defaultSecretId, generateRandomPassword };
