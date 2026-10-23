/**
 * AgentCore Gateway REQUEST interceptor.
 *
 * Runs after the Gateway's CUSTOM_JWT authorizer has validated the bearer
 * token and before the Gateway invokes the Lambda target. Configured with
 * `inputConfiguration.passRequestHeaders: true`, so the payload contains the
 * caller's `Authorization` header:
 *   https://docs.aws.amazon.com/bedrock-agentcore/latest/devguide/gateway-interceptors-types.html
 *   https://docs.aws.amazon.com/bedrock-agentcore/latest/devguide/gateway-interceptors-configuration.html
 *
 * For `tools/call` it rewrites `params.arguments.__caller_token` to the bearer
 * JWT, replacing anything the model sent under that key. That is the only way
 * the caller's verified identity reaches a Lambda target (the Lambda-target
 * contract has no claims field, and `Authorization` can never be allowlisted
 * for header propagation). The tool Lambdas re-verify the token themselves.
 *
 * Non-`tools/call` single JSON-RPC objects (initialize, tools/list,
 * notifications, ping, ...) carry no `params.arguments` to a tool target, but
 * we still defensively scrub `params.arguments.__caller_token` so a client
 * cannot smuggle a reserved value past the interceptor.
 *
 * JSON-RPC batch arrays (MCP 2025-03-26) are handled by applying the same
 * rewrite/scrub to every entry. Any other body shape (string, number, other
 * primitive) is rejected with a JSON-RPC error — we cannot safely scrub what
 * we cannot parse, so we fail closed.
 *
 * If no bearer is present but at least one entry is a `tools/call`, the
 * interceptor answers the call with a JSON-RPC error instead of forwarding a
 * request the tool could not attribute.
 */
"use strict";

const RESERVED_ARG = "__caller_token";

function getHeader(headers, name) {
  if (!headers) return undefined;
  const want = name.toLowerCase();
  for (const [k, v] of Object.entries(headers)) {
    if (k.toLowerCase() === want) return Array.isArray(v) ? v[0] : v;
  }
  return undefined;
}

function bearerFrom(headers) {
  const auth = getHeader(headers, "authorization");
  if (typeof auth !== "string") return null;
  const m = auth.match(/^Bearer\s+(\S+)$/i);
  return m ? m[1] : null;
}

function passThrough(body) {
  return { interceptorOutputVersion: "1.0", mcp: { transformedGatewayRequest: { body } } };
}

function rpcError(body, message) {
  // `body` may be an array, object, or something else; pick a safe id.
  let id = null;
  if (body && !Array.isArray(body) && typeof body === "object" && body.id !== undefined) {
    id = body.id;
  }
  return {
    interceptorOutputVersion: "1.0",
    mcp: {
      transformedGatewayResponse: {
        statusCode: 401,
        body: { jsonrpc: "2.0", id, error: { code: -32001, message } },
      },
    },
  };
}

function isPlainObject(v) {
  return v !== null && typeof v === "object" && !Array.isArray(v);
}

/**
 * Rewrite a single JSON-RPC request object:
 *   - If it is a `tools/call`, overwrite `params.arguments.__caller_token`
 *     with the Gateway-validated bearer.
 *   - Otherwise, scrub `params.arguments.__caller_token` if present so the
 *     reserved key cannot be smuggled through on a non-tools/call method.
 *
 * Returns the possibly-new request object. Non-object entries are returned
 * unchanged (the batch validator rejects those before we get here).
 */
function rewriteRequest(req, token) {
  if (!isPlainObject(req)) return req;
  const params = isPlainObject(req.params) ? { ...req.params } : null;
  const args = params && isPlainObject(params.arguments) ? { ...params.arguments } : null;

  if (req.method === "tools/call") {
    const nextArgs = args ? { ...args } : {};
    nextArgs[RESERVED_ARG] = token;
    const nextParams = { ...(params || {}), arguments: nextArgs };
    return { ...req, params: nextParams };
  }

  // Non-tools/call: scrub reserved key if present, otherwise leave untouched.
  if (args && Object.prototype.hasOwnProperty.call(args, RESERVED_ARG)) {
    delete args[RESERVED_ARG];
    const nextParams = { ...params, arguments: args };
    return { ...req, params: nextParams };
  }
  return req;
}

function hasToolsCall(body) {
  if (isPlainObject(body)) return body.method === "tools/call";
  if (Array.isArray(body)) return body.some((e) => isPlainObject(e) && e.method === "tools/call");
  return false;
}

async function handler(event) {
  const mcp = (event && event.mcp) || {};
  // A RESPONSE interceptor payload carries gatewayResponse; we are only wired
  // as REQUEST, but pass the response through unchanged if ever invoked as one.
  if (mcp.gatewayResponse) {
    return {
      interceptorOutputVersion: "1.0",
      mcp: {
        transformedGatewayResponse: {
          body: mcp.gatewayResponse.body,
          statusCode: mcp.gatewayResponse.statusCode || 200,
        },
      },
    };
  }

  const request = mcp.gatewayRequest || {};
  const body = request.body;

  // Nothing to transform if the Gateway did not supply a body.
  if (body === null || body === undefined) return passThrough(body);

  // Fail closed on body shapes we cannot safely scrub. A string body may be
  // an unparsed JSON-RPC payload carrying the reserved key; we refuse rather
  // than forward it verbatim.
  if (!isPlainObject(body) && !Array.isArray(body)) {
    return rpcError(body, "unsupported request body shape");
  }

  // Batch arrays: validate every entry is a JSON-RPC object, then apply the
  // same rewrite/scrub to each. An empty batch is invalid per JSON-RPC 2.0.
  if (Array.isArray(body)) {
    if (body.length === 0) {
      return rpcError(body, "empty JSON-RPC batch");
    }
    for (const entry of body) {
      if (!isPlainObject(entry)) {
        return rpcError(body, "invalid JSON-RPC batch entry");
      }
    }
    const needsBearer = hasToolsCall(body);
    const token = needsBearer ? bearerFrom(request.headers) : null;
    if (needsBearer && !token) {
      return rpcError(
        body,
        "missing bearer token (interceptor passRequestHeaders must be true)",
      );
    }
    const next = body.map((entry) => rewriteRequest(entry, token));
    return passThrough(next);
  }

  // Single JSON-RPC request object.
  if (body.method !== "tools/call") {
    // Still scrub the reserved key defensively (initialize/tools/list bodies
    // that embed `params.arguments.__caller_token`).
    return passThrough(rewriteRequest(body, null));
  }

  const token = bearerFrom(request.headers);
  if (!token) {
    return rpcError(body, "missing bearer token (interceptor passRequestHeaders must be true)");
  }
  return passThrough(rewriteRequest(body, token));
}

module.exports = { handler, RESERVED_ARG, bearerFrom };
