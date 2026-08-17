class GatewayError extends Error {
  constructor(code, message, status = 500, options = {}) {
    super(message, options);
    this.name = "GatewayError";
    this.code = code;
    this.status = status;
    this.retryable = options.retryable === true;
    this.delaySeconds = options.delaySeconds;
  }
}

function gatewayError(error) {
  if (error instanceof GatewayError) return error;
  const message = String(error?.message || error || "Internal error");
  if (/authentication|token|jwt|session/i.test(message)) {
    return new GatewayError("UNAUTHORIZED", "Authentication failed", 401);
  }
  if (/REVISION_CONFLICT/.test(message)) return new GatewayError("REVISION_CONFLICT", "The record changed", 409);
  if (/JOB_NOT_FOUND/.test(message)) return new GatewayError("JOB_NOT_FOUND", "Job not found", 404);
  if (/FORBIDDEN/.test(message)) return new GatewayError("FORBIDDEN", "Forbidden", 403);
  if (/UNKNOWN_EDGE|UNKNOWN_OPERATION/.test(message)) return new GatewayError("UNKNOWN_EDGE", "Unknown edge function", 404);
  if (error?.code && Number.isInteger(error.status) && error.status >= 400 && error.status <= 599) {
    return new GatewayError(error.code, message, error.status, {
      retryable: error.retryable,
      delaySeconds: error.delaySeconds,
      cause: error,
    });
  }
  if (error?.code === "CREDENTIAL_INPUT_FORBIDDEN") {
    return new GatewayError("CREDENTIAL_INPUT_FORBIDDEN", "Credentials are not accepted in edge arguments", 400);
  }
  return new GatewayError(error?.code || "INTERNAL_ERROR", "Internal error", 500, {
    retryable: error?.retryable,
    delaySeconds: error?.delaySeconds,
    cause: error,
  });
}

function publicError(error, requestId) {
  const normalized = gatewayError(error);
  return {
    status: normalized.status,
    body: {
      ok: false,
      error: { code: normalized.code, message: normalized.message },
      requestId,
    },
  };
}

module.exports = { GatewayError, gatewayError, publicError };
