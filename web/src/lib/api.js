const DEFAULT_TIMEOUT_MS = 8000;
const inflightByKey = new Map();

function parseResponsePayload(text) {
  if (!text) return {};
  try {
    return JSON.parse(text);
  } catch {
    return { message: text };
  }
}

function makeRequestError(message, code = "") {
  const error = new Error(message || "Request failed");
  error.code = code;
  return error;
}

export async function request(path, options = {}) {
  const {
    timeoutMs = DEFAULT_TIMEOUT_MS,
    key = "",
    signal: externalSignal,
    ...fetchOptions
  } = options || {};

  const controller = new AbortController();
  const timeout = window.setTimeout(() => controller.abort("timeout"), Math.max(500, Number(timeoutMs) || DEFAULT_TIMEOUT_MS));
  const cleanup = () => {
    window.clearTimeout(timeout);
    if (key && inflightByKey.get(key)?.controller === controller) {
      inflightByKey.delete(key);
    }
  };

  if (externalSignal) {
    if (externalSignal.aborted) controller.abort(externalSignal.reason || "aborted");
    else externalSignal.addEventListener("abort", () => controller.abort(externalSignal.reason || "aborted"), { once: true });
  }

  if (key) {
    const previous = inflightByKey.get(key);
    if (previous?.controller) previous.controller.abort("superseded");
    inflightByKey.set(key, { controller });
  }

  try {
    const response = await fetch(path, {
      ...fetchOptions,
      headers: {
        "Content-Type": "application/json",
        ...(fetchOptions.headers || {}),
      },
      signal: controller.signal,
    });
    const text = await response.text();
    const payload = parseResponsePayload(text);
    if (!response.ok) {
      const message = payload.error || payload.message || response.statusText || "Request failed";
      if (response.status === 401 || String(message).toLowerCase().includes("authentication required")) {
        throw makeRequestError(message, "AUTH_REQUIRED");
      }
      const error = makeRequestError(message, payload.code || `HTTP_${response.status}`);
      error.status = response.status;
      error.payload = payload;
      throw error;
    }
    return payload;
  } catch (error) {
    if (error?.code === "AUTH_REQUIRED") {
      if (typeof window !== "undefined") {
        window.location.href = "/login";
      }
      throw error;
    }
    if (error?.name === "AbortError") {
      const reason = controller.signal?.reason;
      if (reason === "superseded") throw makeRequestError("Request superseded", "SUPERSEDED");
      if (reason === "timeout") throw makeRequestError("Request timeout", "TIMEOUT");
      throw makeRequestError("Request aborted", "ABORTED");
    }
    throw error;
  } finally {
    cleanup();
  }
}

export async function downloadFile(path, options = {}) {
  const { timeoutMs = 30000, ...fetchOptions } = options || {};
  const controller = new AbortController();
  const timeout = window.setTimeout(() => controller.abort("timeout"), Math.max(1000, Number(timeoutMs) || 30000));
  try {
    const response = await fetch(path, {
      headers: {
        ...(fetchOptions.headers || {}),
      },
      ...fetchOptions,
      signal: controller.signal,
    });
    if (!response.ok) {
      const text = await response.text();
      const payload = parseResponsePayload(text);
      const message = payload.error || payload.message || response.statusText || "Download failed";
      if (response.status === 401 || String(message).toLowerCase().includes("authentication required")) {
        const error = makeRequestError(message, "AUTH_REQUIRED");
        if (typeof window !== "undefined") window.location.href = "/login";
        throw error;
      }
      const error = makeRequestError(message, payload.code || `HTTP_${response.status}`);
      error.status = response.status;
      error.payload = payload;
      throw error;
    }
    const disposition = response.headers.get("Content-Disposition") || "";
    const filenameMatch = disposition.match(/filename="?([^";]+)"?/i);
    return {
      blob: await response.blob(),
      filename: filenameMatch?.[1] || "nodewall-report",
    };
  } catch (error) {
    if (error?.name === "AbortError") throw makeRequestError("Request timeout", "TIMEOUT");
    throw error;
  } finally {
    window.clearTimeout(timeout);
  }
}

export function withDirection(path, direction) {
  const separator = path.includes("?") ? "&" : "?";
  return `${path}${separator}direction=${encodeURIComponent(direction || "ingress")}`;
}
