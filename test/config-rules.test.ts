import assert from "node:assert/strict";
import test from "node:test";
import { assertAutoApproveDisabled, parseAllowedHosts, validateToken } from "../src/config-rules.js";

test("assertAutoApproveDisabled strictly blocks any auto-approval enablement", () => {
  // Disallowed values must throw
  assert.throws(() => assertAutoApproveDisabled("true"), /no longer supported/);
  assert.throws(() => assertAutoApproveDisabled("TRUE"), /no longer supported/);
  assert.throws(() => assertAutoApproveDisabled("1"), /no longer supported/);
  assert.throws(() => assertAutoApproveDisabled("yes"), /no longer supported/);
  assert.throws(() => assertAutoApproveDisabled("enable"), /no longer supported/);

  // Allowed / disabled values must pass
  assert.doesNotThrow(() => assertAutoApproveDisabled(undefined));
  assert.doesNotThrow(() => assertAutoApproveDisabled(""));
  assert.doesNotThrow(() => assertAutoApproveDisabled("false"));
  assert.doesNotThrow(() => assertAutoApproveDisabled("0"));
  assert.doesNotThrow(() => assertAutoApproveDisabled("no"));
});

test("validateToken enforces length, uniqueness, and rejects placeholders", () => {
  // Too short (<32 chars)
  assert.throws(() => validateToken("short-token"), /at least 32 characters/);
  assert.throws(() => validateToken("1234567890123456789012345678901"), /at least 32 characters/);

  // Placeholders
  assert.throws(() => validateToken("replace-this-with-a-real-secret-123456"), /placeholder/);
  assert.throws(() => validateToken("placeholder-secret-value-0123456789abc"), /placeholder/);
  assert.throws(() => validateToken("change-me-secret-token-value-012345678"), /placeholder/);
  assert.throws(() => validateToken("example-token-value-string-0123456789a"), /placeholder/);
  assert.throws(() => validateToken("your-secret-key-goes-here-012345678901"), /placeholder/);

  // Low variety (<10 unique chars)
  assert.throws(() => validateToken("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"), /placeholder|predictable/);
  assert.throws(() => validateToken("abababababababababababababababab"), /placeholder|predictable/);

  // Valid token passes and is returned
  const valid = "a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6";
  assert.equal(validateToken(valid), valid);
});

test("parseAllowedHosts validates and normalizes host lists", () => {
  assert.deepEqual(parseAllowedHosts(""), []);
  assert.deepEqual(parseAllowedHosts(undefined), []);
  assert.deepEqual(parseAllowedHosts("example.com, Sub.Domain.Org "), ["example.com", "sub.domain.org"]);

  assert.throws(() => parseAllowedHosts("http://example.com"), /host names/);
  assert.throws(() => parseAllowedHosts("example.com:8080"), /host names/);
  assert.throws(() => parseAllowedHosts("example.com/path"), /host names/);
});
