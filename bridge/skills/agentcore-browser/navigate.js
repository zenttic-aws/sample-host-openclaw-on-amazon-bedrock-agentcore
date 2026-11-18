"use strict";
const {
  connectBrowser,
  applyStealthHeaders,
  truncateContent,
  validateTargetUrl,
  installSsrfRouteGuard,
  CONTENT_TRUNCATE_CHARS,
  NAV_TIMEOUT_MS,
} = require("./common");

async function browserNavigate(args) {
  const { url } = args;
  if (!url) return JSON.stringify({ error: "url is required" });

  // Enforce SSRF policy BEFORE opening a browser session: scheme allowlist
  // (only http/https; blocks file:, chrome:, devtools:, view-source:, data:,
  // blob:, ftp:, ...) and DNS-resolved host checks (reject loopback,
  // link-local 169.254/16, ::1, RFC1918, CGNAT, multicast, and any extra
  // CIDRs configured via BROWSER_BLOCKED_CIDRS, e.g. the VPC CIDR).
  let safeUrl;
  try {
    safeUrl = await validateTargetUrl(url);
  } catch (err) {
    return JSON.stringify({ error: `url rejected: ${err.message}` });
  }

  const { page, disconnect } = await connectBrowser();
  try {
    await applyStealthHeaders(page);
    // Re-apply the same policy to every request the page issues, including
    // redirect hops and subresources. If the host’s DNS rebinds mid-session,
    // the route handler aborts the follow-up request.
    await installSsrfRouteGuard(page);
    await page.goto(safeUrl, { waitUntil: "domcontentloaded", timeout: NAV_TIMEOUT_MS });
    const title = await page.title();

    // Extract readable text — remove script/style noise
    let content = "";
    try {
      content = await page.evaluate(() => {
        const clone = document.cloneNode(true);
        clone.querySelectorAll("script, style, noscript, iframe").forEach(el => el.remove());
        return clone.body?.innerText || clone.body?.textContent || "";
      });
    } catch (_) {
      // Execution context may be destroyed during navigation — title is enough as fallback
    }

    return JSON.stringify({
      // Mark the returned payload as untrusted tool output so callers
      // (prompt builders) do not treat it as model instructions.
      source: "untrusted-web-content",
      url: page.url(),
      title,
      content: truncateContent(content.replace(/\s+/g, " ").trim(), CONTENT_TRUNCATE_CHARS),
    });
  } catch (err) {
    if (err.message.includes("Browser session not available")) {
      return JSON.stringify({ error: "Browser is not available. The enable_browser feature must be enabled in CDK configuration." });
    }
    return JSON.stringify({ error: `Navigation failed: ${err.message}` });
  } finally {
    await disconnect();
  }
}

// CLI entrypoint (called by OpenClaw)
const args = JSON.parse(process.argv[2] || "{}");
browserNavigate(args).then(console.log).catch(err => console.log(JSON.stringify({ error: err.message })));
