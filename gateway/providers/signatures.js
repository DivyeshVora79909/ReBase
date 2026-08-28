const crypto = require("node:crypto");

function verifyHmacSha256(rawBody, signature, secret) {
  if (!signature || !secret) return false;
  const expected = crypto
    .createHmac("sha256", String(secret))
    .update(rawBody)
    .digest("hex");
  const actual = Buffer.from(String(signature).replace(/^sha256=/i, ""), "utf8");
  const wanted = Buffer.from(expected, "utf8");
  return actual.length === wanted.length && crypto.timingSafeEqual(actual, wanted);
}

function parseJson(rawBody) {
  try {
    return JSON.parse(rawBody);
  } catch {
    return null;
  }
}

module.exports = { parseJson, verifyHmacSha256 };
