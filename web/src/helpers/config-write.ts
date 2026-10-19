import type { AxiosRequestConfig } from "axios";
import request from "./request";
/** A config apply waits one 10-second reload window server-side. Allow another
 * ordinary request window for validation/transport, retaining a finite bound. */
export async function putConfig<T>(
  path: string,
  body: unknown,
  config: AxiosRequestConfig = {},
): Promise<T> {
  try {
    return (await request.put<T>(path, body, { timeout: 20000, ...config }))
      .data;
  } catch (error) {
    if (
      error &&
      typeof error === "object" &&
      "category" in error &&
      error.category === "timeout"
    ) {
      // Read only. A response timeout does not prove the server rejected the write.
      // Failed reconciliation must not hide the original uncertain outcome.
      await request.get("/config-versions", config).catch(() => undefined);
    }
    throw error;
  }
}
