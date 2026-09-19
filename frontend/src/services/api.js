const API_BASE_URL = import.meta.env.VITE_API_BASE_URL || "http://localhost:8000";

/**
 * Sends the authorized lab target URL to the backend for controlled SSRF
 * detection checks. Never call this against a target you do not own or
 * have explicit authorization to test.
 */
export async function scanTarget(targetUrl) {
  let response;
  try {
    response = await fetch(`${API_BASE_URL}/scan`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ target_url: targetUrl }),
    });
  } catch (networkError) {
    throw new ApiError(
      "Could not reach the backend API. Is the FastAPI server running on " +
        API_BASE_URL +
        "?",
      0
    );
  }

  let payload = null;
  try {
    payload = await response.json();
  } catch {
    // Non-JSON body; fall through to generic error below.
  }

  if (!response.ok) {
    const detail =
      (payload && payload.detail) ||
      "The scan could not be completed. Please check the target URL and try again.";
    throw new ApiError(detail, response.status);
  }

  return payload;
}

export class ApiError extends Error {
  constructor(message, status) {
    super(message);
    this.name = "ApiError";
    this.status = status;
  }
}
