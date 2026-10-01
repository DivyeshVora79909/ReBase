const crypto = require("node:crypto");

const ALGORITHM = "aes-256-gcm";
const DOMAIN = "rebase:authentication-delivery:v1\0";

function createAuthenticationPayloadCipher(payloadSecret) {
  if (typeof payloadSecret !== "string" || payloadSecret.length < 1) {
    throw new Error("Authentication delivery encryption requires its payload secret");
  }
  const key = crypto.createHash("sha256").update(DOMAIN).update(payloadSecret).digest();

  function seal(value) {
    const iv = crypto.randomBytes(12);
    const cipher = crypto.createCipheriv(ALGORITHM, key, iv);
    const ciphertext = Buffer.concat([
      cipher.update(JSON.stringify(value), "utf8"),
      cipher.final(),
    ]);
    return Buffer.concat([iv, cipher.getAuthTag(), ciphertext]).toString("base64url");
  }

  function open(encoded) {
    if (typeof encoded !== "string" || !/^[A-Za-z0-9_-]+$/.test(encoded)) {
      throw new Error("Authentication delivery payload is malformed");
    }
    const packed = Buffer.from(encoded, "base64url");
    if (packed.length < 29) throw new Error("Authentication delivery payload is malformed");
    const decipher = crypto.createDecipheriv(ALGORITHM, key, packed.subarray(0, 12));
    decipher.setAuthTag(packed.subarray(12, 28));
    const plaintext = Buffer.concat([
      decipher.update(packed.subarray(28)),
      decipher.final(),
    ]).toString("utf8");
    return JSON.parse(plaintext);
  }

  return Object.freeze({ seal, open });
}

module.exports = { createAuthenticationPayloadCipher };
