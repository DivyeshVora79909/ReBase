function normalizeEmail(value) {
  const email = typeof value === "string" ? value.trim().toLowerCase() : "";
  return email && email.includes("@") && !/\s/.test(email) ? email : null;
}

function adapterEntries(adapters) {
  if (adapters instanceof Map) return [...adapters.entries()];
  return Object.entries(adapters || {});
}

function createOAuthVerifier(adapters = {}, options = {}) {
  const providers = new Map(adapterEntries(adapters).map(([name, adapter]) => {
    const normalized = String(name).trim().toLowerCase();
    if (!normalized) throw new Error("OAuth provider names must not be empty");
    if (typeof adapter !== "function") {
      throw new Error(`OAuth verifier ${normalized} must be a function`);
    }
    return [normalized, adapter];
  }));
  return Object.freeze({
    providers: Object.freeze([...providers.keys()].sort()),
    async verify(providerName, providerToken) {
      const name = String(providerName || "").trim().toLowerCase();
      const token = typeof providerToken === "string" ? providerToken.trim() : "";
      const adapter = providers.get(name);
      if (!adapter || !token) return { verified: false };
      try {
        const result = await adapter(token);
        const email = result?.verified === true ? normalizeEmail(result.email) : null;
        return email ? { verified: true, email } : { verified: false };
      } catch (error) {
        options.onError?.({ provider: name, code: String(error?.code || "OAUTH_VERIFICATION_FAILED") });
        return { verified: false };
      }
    },
    async health() {
      return { ok: true, configuredProviders: [...providers.keys()].sort() };
    },
  });
}

function createMockOAuthAdapter(tokens = {}) {
  const known = tokens instanceof Map ? new Map(tokens) : new Map(Object.entries(tokens));
  return async function verifyMockOAuth(token) {
    const email = normalizeEmail(known.get(String(token)));
    return email ? { verified: true, email } : { verified: false };
  };
}

module.exports = { createMockOAuthAdapter, createOAuthVerifier, normalizeEmail };
