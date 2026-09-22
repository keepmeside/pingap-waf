import { useQuery, type UseQueryResult } from "@tanstack/react-query";
import request from "@/helpers/request";

export type ApiState<T> = { data: T; unavailable: false } | { data: null; unavailable: true; message: string };

async function fetchEndpoint<T>(path: string): Promise<ApiState<T>> {
  try {
    const response = await request.get<T>(path);
    return { data: response.data, unavailable: false };
  } catch (error) {
    const status = typeof error === "object" && error !== null && "status" in error ? Number(error.status) : 0;
    if (status === 404 || status === 501) {
      return { data: null, unavailable: true, message: "This endpoint is not available on the connected server." };
    }
    throw error;
  }
}

export function useAdminEndpoint<T>(key: string, path: string): UseQueryResult<ApiState<T>, Error> {
  return useQuery({
    queryKey: ["admin", key],
    queryFn: () => fetchEndpoint<T>(path),
    staleTime: 10_000,
    refetchInterval: 30_000,
  });
}
