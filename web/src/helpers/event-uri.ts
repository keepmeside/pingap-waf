/** Return only the request path for security event display. */
export function safeEventUri(uri?: string | null): string {
  if (!uri) return "URI not captured";
  return uri.split("?", 1)[0] || "/";
}
