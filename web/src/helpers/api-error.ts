/** Read public API error fields only; never stringify arbitrary server objects. */
export function apiErrorMessage(
  data: unknown,
  fallback = "Unknown error",
): string {
  if (typeof data === "string") return data.trim() || fallback;
  if (!data || typeof data !== "object") return fallback;
  const fields = data as Record<string, unknown>;
  const message =
    typeof fields.message === "string"
      ? fields.message
      : typeof fields.error === "string"
        ? fields.error
        : fallback;
  const action = typeof fields.action === "string" ? fields.action : "";
  return action ? `${message}. ${action}` : message;
}
