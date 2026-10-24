/**
 * Tests for s3-user-files common utilities.
 * Run: node --test common.test.js
 */
const { describe, it } = require("node:test");
const assert = require("node:assert/strict");
const { sanitize, buildKey, validateUserId } = require("./common");

describe("sanitize", () => {
  it("passes through simple alphanumeric strings", () => {
    assert.equal(sanitize("telegram_12345"), "telegram_12345");
  });

  it("replaces colons with underscores", () => {
    assert.equal(sanitize("telegram:12345"), "telegram_12345");
  });

  it("removes path traversal sequences", () => {
    // ".." removed, remaining "/" become "_"
    assert.equal(sanitize("../../../etc/passwd"), "___etc_passwd");
  });

  it("replaces slashes with underscores", () => {
    assert.equal(sanitize("foo/bar/baz"), "foo_bar_baz");
  });

  it("allows hyphens and dots", () => {
    assert.equal(sanitize("my-file.md"), "my-file.md");
  });

  it("truncates to 256 characters", () => {
    const long = "a".repeat(300);
    assert.equal(sanitize(long).length, 256);
  });

  it("handles empty string", () => {
    assert.equal(sanitize(""), "");
  });

  it("replaces spaces with underscores", () => {
    assert.equal(sanitize("John Doe"), "John_Doe");
  });

  it("handles Slack user IDs", () => {
    assert.equal(sanitize("slack:U0123456789"), "slack_U0123456789");
  });

  it("iteratively removes nested dot-dot sequences", () => {
    // "......" (6 dots) -> first pass removes 3 pairs -> ""
    assert.equal(sanitize("......"), "");
    // "....." (5 dots) -> first pass removes 2 pairs -> "." -> rejected (leading dot)
    assert.throws(() => sanitize("....."), /leading\/trailing dots not allowed/);
  });

  it("rejects leading dots in filenames", () => {
    assert.throws(() => sanitize(".hidden"), /leading\/trailing dots not allowed/);
    assert.throws(() => sanitize(".env"), /leading\/trailing dots not allowed/);
  });

  it("rejects trailing dots in filenames", () => {
    assert.throws(() => sanitize("file."), /leading\/trailing dots not allowed/);
  });
});

describe("buildKey", () => {
  it("builds key with userId and filename", () => {
    assert.equal(
      buildKey("telegram_12345", "IDENTITY.md"),
      "telegram_12345/IDENTITY.md",
    );
  });

  it("sanitizes userId in key", () => {
    assert.equal(
      buildKey("telegram:12345", "notes.md"),
      "telegram_12345/notes.md",
    );
  });

  it("returns prefix with trailing slash when no filename", () => {
    assert.equal(buildKey("telegram_12345"), "telegram_12345/");
  });

  it("sanitizes both userId and filename", () => {
    assert.equal(
      buildKey("../admin", "../../etc/passwd"),
      "_admin/__etc_passwd",
    );
  });
});

describe("validateUserId", () => {
  // validateUserId now requires the argv namespace to equal the container's
  // own identity (resolved from /tmp/current-identity.json or USER_ID). Tests
  // bind USER_ID to the namespace they expect to be accepted, and clear it
  // afterwards. The identity file is not present in the test environment, so
  // the env-var fallback is exercised.
  function withOwnIdentity(ownNamespace, fn) {
    const prevUserId = process.env.USER_ID;
    const prevInternal = process.env.INTERNAL_USER_ID;
    // actorId uses ':' which validateUserId maps to '_' before comparing.
    process.env.USER_ID = ownNamespace.replace(/_/, ":");
    delete process.env.INTERNAL_USER_ID;
    try {
      fn();
    } finally {
      if (prevUserId === undefined) delete process.env.USER_ID;
      else process.env.USER_ID = prevUserId;
      if (prevInternal === undefined) delete process.env.INTERNAL_USER_ID;
      else process.env.INTERNAL_USER_ID = prevInternal;
    }
  }

  function expectExit(fn) {
    const originalExit = process.exit;
    let exitCode = null;
    process.exit = (code) => {
      exitCode = code;
      throw new Error("process.exit called");
    };
    try {
      assert.throws(fn, /process\.exit/);
      assert.equal(exitCode, 1);
    } finally {
      process.exit = originalExit;
    }
  }

  it("accepts valid telegram namespace when it matches own identity", () => {
    withOwnIdentity("telegram_123456789", () => {
      assert.doesNotThrow(() => validateUserId("telegram_123456789"));
    });
  });

  it("accepts valid slack namespace when it matches own identity", () => {
    withOwnIdentity("slack_sen-outlook", () => {
      assert.doesNotThrow(() => validateUserId("slack_sen-outlook"));
    });
  });

  it("accepts valid discord namespace when it matches own identity", () => {
    withOwnIdentity("discord_123456789012345678", () => {
      assert.doesNotThrow(() => validateUserId("discord_123456789012345678"));
    });
  });

  it("accepts valid line namespace when it matches own identity", () => {
    withOwnIdentity("line_U0000000000000000000000000000001", () => {
      assert.doesNotThrow(() => validateUserId("line_U0000000000000000000000000000001"));
    });
  });

  it("accepts valid slack namespace with uppercase ID when it matches own identity", () => {
    withOwnIdentity("slack_U0XXXXXXXX1", () => {
      assert.doesNotThrow(() => validateUserId("slack_U0XXXXXXXX1"));
    });
  });

  it("rejects empty userId", () => {
    withOwnIdentity("telegram_123456789", () => {
      expectExit(() => validateUserId(""));
    });
  });

  it("rejects default-user", () => {
    withOwnIdentity("telegram_123456789", () => {
      expectExit(() => validateUserId("default-user"));
    });
  });

  it("rejects arbitrary namespace without channel prefix", () => {
    withOwnIdentity("telegram_123456789", () => {
      expectExit(() => validateUserId("my-custom-id"));
    });
  });

  it("rejects path traversal attempts", () => {
    withOwnIdentity("telegram_123456789", () => {
      expectExit(() => validateUserId("../other_user"));
    });
  });

  it("rejects a format-valid namespace that is not the container's own", () => {
    // The core of the fix: a well-formed channel_identifier for another
    // tenant must be refused even though it passes the regex.
    withOwnIdentity("telegram_123456789", () => {
      expectExit(() => validateUserId("telegram_987654321"));
    });
  });

  it("rejects when the container has no resolvable identity", () => {
    const prevUserId = process.env.USER_ID;
    const prevInternal = process.env.INTERNAL_USER_ID;
    delete process.env.USER_ID;
    delete process.env.INTERNAL_USER_ID;
    try {
      expectExit(() => validateUserId("telegram_123456789"));
    } finally {
      if (prevUserId !== undefined) process.env.USER_ID = prevUserId;
      if (prevInternal !== undefined) process.env.INTERNAL_USER_ID = prevInternal;
    }
  });
});
