export type PluginConfig = Record<string, unknown>;

const NATIVE_PLUGIN_CATEGORIES = new Set([
  "behaviour",
  "challenge",
  "adaptive",
]);

/**
 * The advanced plugin form only exposes the common fields for native profiles.
 * Keep the fields it does not render when submitting an existing native profile;
 * the dedicated policy controls remain responsible for intentional native edits.
 */
export function mergeNativePluginConfig(
  category: unknown,
  existing: PluginConfig,
  draft: PluginConfig,
): PluginConfig {
  if (
    !NATIVE_PLUGIN_CATEGORIES.has(String(category)) ||
    Object.keys(existing).length === 0
  ) {
    return draft;
  }
  return { ...existing, ...draft };
}
