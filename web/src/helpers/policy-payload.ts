import type { PluginConf } from "@/lib/types";
/** Keep the complete config; category is validated, never guessed from a body. */
export function policyPayload(entry: string, body: PluginConf): PluginConf {
  const split = entry.indexOf(":");
  if (split <= 0 || !entry.slice(split + 1).trim())
    throw new Error("Policy name must be category:profile");
  const category = entry.slice(0, split);
  if (body.category !== undefined && body.category !== category)
    throw new Error("Policy category must match its entry name");
  const config: PluginConf = { ...body, category };
  if (category === "challenge") {
    delete config.secret_configured; delete config.secret_source;
    return { config };
  }
  return config;
}
