function adapterError(code, message, status, retryable = false, cause) {
  const error = new Error(message, { cause });
  error.code = code;
  error.status = status;
  error.retryable = retryable;
  return error;
}

async function responseBody(response) {
  const text = await response.text();
  if (!text) return {};
  try {
    return JSON.parse(text);
  } catch {
    return { message: text.slice(0, 500) };
  }
}

function isRetryableStatus(status) {
  return status === 408 || status === 429 || status >= 500;
}

module.exports = { adapterError, isRetryableStatus, responseBody };
