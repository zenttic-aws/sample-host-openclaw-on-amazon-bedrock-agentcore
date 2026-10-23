"use strict";
const fs = require("fs");
const dns = require("dns").promises;
const net = require("net");

const BROWSER_SESSION_FILE = "/tmp/agentcore-browser-session.json";
const CONTENT_TRUNCATE_CHARS = 8000;
const NAV_TIMEOUT_MS = 30000;
const INTERACT_TIMEOUT_MS = 10000;
const WAIT_TIMEOUT_MS = 15000;

// Accepting invalid TLS certificates is a security-posture change: it disables
// certificate validation for ALL browsing in this context. Keep it OFF by
// default and require an explicit opt-in via BROWSER_IGNORE_HTTPS_ERRORS=true,
// intended only for VPC environments that terminate TLS with a private CA.
const IGNORE_HTTPS_ERRORS = process.env.BROWSER_IGNORE_HTTPS_ERRORS === "true";

function getBrowserSession() {
  if (!fs.existsSync(BROWSER_SESSION_FILE)) {
    throw new Error(
      "Browser session not available. Ensure enable_browser=true in CDK config and that the session has been initialized."
    );
  }
  const data = JSON.parse(fs.readFileSync(BROWSER_SESSION_FILE, "utf8"));
  if (!data.endpoint) throw new Error("Browser session file missing endpoint");
  return data;
}

async function connectBrowser() {
  const session = getBrowserSession();
  const { chromium } = require("playwright-core");
  const browser = await chromium.connectOverCDP(session.endpoint, {
    timeout: 15000,
    headers: session.headers || {},
  });
  const contexts = browser.contexts();
  const context = contexts.length > 0 ? contexts[0] : await browser.newContext({ ignoreHTTPSErrors: IGNORE_HTTPS_ERRORS });
  const pages = context.pages();
  const page = pages.length > 0 ? pages[0] : await context.newPage();
  return {
    browser,
    page,
    disconnect: async () => {
      try { await browser.close(); } catch {}
    },
  };
}

async function uploadScreenshotToS3(imageBuffer) {
  const bucket = process.env.S3_USER_FILES_BUCKET;
  if (!bucket) {
    throw new Error("S3_USER_FILES_BUCKET environment variable is not set — cannot upload screenshot");
  }
  const userId = process.env.USER_ID || "default-user";
  const namespace = userId.replace(/:/g, "_");
  const timestamp = Date.now();
  const key = `${namespace}/_screenshots/screenshot_${timestamp}.png`;

  const { S3Client, PutObjectCommand } = require("@aws-sdk/client-s3");
  const client = new S3Client({ region: process.env.AWS_REGION || "us-east-1" });
  await client.send(new PutObjectCommand({
    Bucket: bucket,
    Key: key,
    Body: imageBuffer,
    ContentType: "image/png",
  }));
  return key;
}

function truncateContent(text, maxChars) {
  if (text.length <= maxChars) return text;
  return text.slice(0, maxChars) + `\n\n[Content truncated at ${maxChars} characters]`;
}

// --- URL / destination validation (SSRF defense) ---
//
// The browser skill is driven by LLM/chat-user input. Even though the caller
// has other means of reaching the same network position, we still enforce
// scheme and destination-IP checks here so the tool cannot be coaxed into
// reading `file://` paths, probing the sandbox loopback, hitting link-local
// metadata services, or being used as a blind redirect-based SSRF channel.
// Callers can relax the policy per-invocation only through environment
// configuration, not through tool arguments.

const ALLOWED_SCHEMES = new Set(["http:", "https:"]);

// Comma-separated extra CIDRs (e.g. the VPC CIDR) that must also be refused.
// Example: BROWSER_BLOCKED_CIDRS="10.0.0.0/16,10.1.0.0/16"
function getExtraBlockedCidrs() {
  const raw = process.env.BROWSER_BLOCKED_CIDRS || "";
  return raw.split(",").map(s => s.trim()).filter(Boolean);
}

// Optional explicit host allowlist. If set (comma-separated), only exact
// hostname matches are permitted after scheme/IP checks.
function getHostAllowlist() {
  const raw = process.env.BROWSER_HOST_ALLOWLIST || "";
  const items = raw.split(",").map(s => s.trim().toLowerCase()).filter(Boolean);
  return items.length ? new Set(items) : null;
}

function ipv4ToInt(ip) {
  const parts = ip.split(".").map(Number);
  if (parts.length !== 4 || parts.some(n => !Number.isInteger(n) || n < 0 || n > 255)) return null;
  return ((parts[0] << 24) >>> 0) + (parts[1] << 16) + (parts[2] << 8) + parts[3];
}

function ipv4InCidr(ip, cidr) {
  const [range, bitsStr] = cidr.split("/");
  const bits = Number(bitsStr);
  const ipInt = ipv4ToInt(ip);
  const rangeInt = ipv4ToInt(range);
  if (ipInt === null || rangeInt === null || !Number.isInteger(bits) || bits < 0 || bits > 32) return false;
  if (bits === 0) return true;
  const mask = (~0 << (32 - bits)) >>> 0;
  return (ipInt & mask) === (rangeInt & mask);
}

const BLOCKED_IPV4_CIDRS = [
  "0.0.0.0/8",         // "this network"
  "10.0.0.0/8",        // RFC1918
  "100.64.0.0/10",     // CGNAT
  "127.0.0.0/8",       // loopback
  "169.254.0.0/16",    // link-local (incl. 169.254.169.254 metadata)
  "172.16.0.0/12",     // RFC1918
  "192.0.0.0/24",      // IETF protocol assignments
  "192.0.2.0/24",      // TEST-NET-1
  "192.168.0.0/16",    // RFC1918
  "198.18.0.0/15",     // benchmark
  "198.51.100.0/24",   // TEST-NET-2
  "203.0.113.0/24",    // TEST-NET-3
  "224.0.0.0/4",       // multicast
  "240.0.0.0/4",       // reserved
  "255.255.255.255/32",// broadcast
];

function normalizeIpv6(ip) {
  // net.isIPv6 accepts things like "::ffff:127.0.0.1" — expose that form.
  return ip.toLowerCase();
}

function isBlockedIpv6(ip) {
  const low = normalizeIpv6(ip);
  if (low === "::" || low === "::1") return true;              // unspecified / loopback
  if (low.startsWith("fe80:") || low.startsWith("fe80::")) return true; // link-local
  if (/^fe[89ab][0-9a-f]:/.test(low)) return true;             // link-local range fe80::/10
  if (/^f[cd][0-9a-f]{2}:/.test(low)) return true;             // ULA fc00::/7
  if (low.startsWith("ff")) return true;                       // multicast ff00::/8
  if (low.startsWith("::ffff:")) {
    const v4 = low.slice("::ffff:".length);
    if (net.isIPv4(v4)) return isBlockedIpv4(v4);
  }
  if (low.startsWith("64:ff9b::")) return true;                // NAT64 well-known
  return false;
}

function isBlockedIpv4(ip) {
  for (const cidr of BLOCKED_IPV4_CIDRS) {
    if (ipv4InCidr(ip, cidr)) return true;
  }
  for (const cidr of getExtraBlockedCidrs()) {
    if (cidr.includes(":")) continue; // IPv6 CIDR not supported here
    if (ipv4InCidr(ip, cidr)) return true;
  }
  return false;
}

function isBlockedIp(ip) {
  if (net.isIPv4(ip)) return isBlockedIpv4(ip);
  if (net.isIPv6(ip)) return isBlockedIpv6(ip);
  return true; // unknown family — refuse
}

// Parse + scheme + hostname-shape checks only (synchronous).
function parseTargetUrl(input) {
  let parsed;
  try {
    parsed = new URL(input);
  } catch {
    throw new Error("url is not a valid absolute URL");
  }
  if (!ALLOWED_SCHEMES.has(parsed.protocol)) {
    throw new Error(`url scheme not allowed: ${parsed.protocol.replace(/:$/, "")} (only http, https)`);
  }
  if (!parsed.hostname) {
    throw new Error("url is missing a hostname");
  }
  // Strip IPv6 brackets for raw-IP checks.
  let host = parsed.hostname;
  if (host.startsWith("[") && host.endsWith("]")) host = host.slice(1, -1);

  // Reject obvious host-form shortcuts even before DNS.
  const lowHost = host.toLowerCase();
  if (lowHost === "localhost" || lowHost.endsWith(".localhost") || lowHost === "localhost.localdomain") {
    throw new Error("url host is not allowed (loopback)");
  }

  if (net.isIP(host)) {
    if (isBlockedIp(host)) {
      throw new Error(`url host is not allowed (blocked IP range): ${host}`);
    }
  }

  const allowlist = getHostAllowlist();
  if (allowlist && !allowlist.has(lowHost)) {
    throw new Error(`url host is not on the configured allowlist: ${lowHost}`);
  }

  return { parsed, host, lowHost };
}

// Full validation: scheme + hostname + DNS resolution of every A/AAAA answer.
async function validateTargetUrl(input) {
  const { parsed, host } = parseTargetUrl(input);
  if (!net.isIP(host)) {
    let records;
    try {
      records = await dns.lookup(host, { all: true, verbatim: true });
    } catch (err) {
      throw new Error(`url host could not be resolved: ${host} (${err.code || err.message})`);
    }
    if (!records || records.length === 0) {
      throw new Error(`url host resolved to no addresses: ${host}`);
    }
    for (const rec of records) {
      if (isBlockedIp(rec.address)) {
        throw new Error(`url host resolves to a blocked IP: ${host} -> ${rec.address}`);
      }
    }
  }
  return parsed.toString();
}

// Playwright route handler that re-applies the SSRF policy on every
// navigation/subresource request (covers redirects, iframes, XHR, etc.).
function installSsrfRouteGuard(page) {
  return page.route("**/*", async (route, request) => {
    try {
      await validateTargetUrl(request.url());
      await route.continue();
    } catch (err) {
      try { await route.abort("accessdenied"); } catch {}
    }
  });
}

const STEALTH_USER_AGENT =
  "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36";

async function applyStealthHeaders(page) {
  await page.addInitScript(() => {
    Object.defineProperty(navigator, "webdriver", { get: () => undefined });
    Object.defineProperty(navigator, "plugins", { get: () => [1, 2, 3, 4, 5] });
    Object.defineProperty(navigator, "languages", { get: () => ["en-US", "en"] });
    window.chrome = { runtime: {} };
  });
  await page.setExtraHTTPHeaders({
    "User-Agent": STEALTH_USER_AGENT,
    "Accept-Language": "en-US,en;q=0.9",
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
  });
}

module.exports = {
  getBrowserSession,
  connectBrowser,
  applyStealthHeaders,
  uploadScreenshotToS3,
  truncateContent,
  parseTargetUrl,
  validateTargetUrl,
  installSsrfRouteGuard,
  isBlockedIp,
  CONTENT_TRUNCATE_CHARS,
  NAV_TIMEOUT_MS,
  INTERACT_TIMEOUT_MS,
  WAIT_TIMEOUT_MS,
};
