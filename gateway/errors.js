class RuntimeError extends Error {
  constructor(code, message, status = 500, options = {}) {
    super(message, options);
    this.name = "RuntimeError";
    this.code = code;
    this.status = status;
    this.retryable = options.retryable === true;
    this.delaySeconds = options.delaySeconds;
  }
}

function runtimeError(error) {
  if (error instanceof RuntimeError) return error;
  const message = String(error?.message || error || "Internal error");
  if (error?.code && Number.isInteger(error.status) && error.status >= 400 && error.status <= 599) {
    return new RuntimeError(error.code, message, error.status, {
      retryable: error.retryable,
      delaySeconds: error.delaySeconds,
      cause: error,
    });
  }
  return new RuntimeError(error?.code || "INTERNAL_ERROR", "Internal error", 500, {
    retryable: error?.retryable,
    delaySeconds: error?.delaySeconds,
    cause: error,
  });
}

function publicError(error) {
  const normalized = runtimeError(error);
  return {
    status: normalized.status,
    body: {
      ok: false,
      error: { code: normalized.code, message: normalized.message },
    },
  };
}

module.exports = { RuntimeError, publicError, runtimeError };
