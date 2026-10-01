// Typed TanStack Query hooks for the admin API — one hook per route-table endpoint.
//
// Two conventions hold the file together:
//
// - **Reads** go through `useAdminEndpoint`, which wraps each call in an `ApiState`:
//   a 404/501 becomes `{unavailable: true}` rather than a thrown error, so a route backed
//   by a subsystem that is not wired (nodes on a single-node deployment, backup with no
//   `backup_dir`) renders "not available" instead of a crash-shaped error.
// - **Writes** are thin `useMutation` wrappers that invalidate the read's key on settle,
//   so the listing a write just changed refetches without the page hand-managing it.
//
// Query keys are `["admin", key]`, with the key namespaced by resource so a mutation to
// `domains` does not evict `users`. A mutation that produces a config version also touches
// `config-versions` and `activity` — the projection and the audit trail both moved.

import {
  useMutation,
  useQuery,
  useQueryClient,
  type UseQueryResult,
} from "@tanstack/react-query";
import request from "@/helpers/request";
import type { ApiState } from "@/queries/api";
import type {
  Activity, AlertHistory, AlertRuleRecord, BackupFileRecord, BackupScheduleRecord,
  BackupView, CertificateView, ConfigStatus, Dashboard, Domain, Health, Listener,
  NodeView, NotificationChannel, PerformanceMetricRecord, PluginConf, Profile,
  RollbackResult, SecondFactorSetup, SecondFactorStatus, SessionView, Upstream,
  UserView, VersionView, WafCategory, WafEventRecord,
} from "@/lib/types";

export type { ApiState };

// ---- reads ---------------------------------------------------------------------------

function useGet<T>(key: string, path: string): UseQueryResult<ApiState<T>, Error> {
  return useQuery({
    queryKey: ["admin", key],
    queryFn: async (): Promise<ApiState<T>> => {
      try {
        const res = await request.get<T>(path);
        return { data: res.data, unavailable: false };
      } catch (error) {
        const status =
          typeof error === "object" && error !== null && "status" in error
            ? Number((error as { status?: number }).status)
            : 0;
        if (status === 404 || status === 501 || status === 503) {
          return {
            data: null,
            unavailable: true,
            message:
              "This endpoint is not available on the connected server.",
          };
        }
        throw error;
      }
    },
    staleTime: 10_000,
    refetchInterval: 30_000,
  });
}

export const useHealth = () => useGet<Health>("health", "/health");
export const useDashboard = () => useGet<Dashboard>("dashboard", "/dashboard");
export const usePerformance = (params = "") =>
  useGet<PerformanceMetricRecord[]>(`performance${params}`, `/performance${params}`);
export const useDomains = () =>
  useGet<Record<string, Domain>>("domains", "/domains");
export const useDomain = (name: string) =>
  useGet<Domain>(`domain:${name}`, `/domains/${encodeURIComponent(name)}`);
export const useUpstreams = () =>
  useGet<Record<string, Upstream>>("upstreams", "/upstreams");
export const useListeners = () =>
  useGet<Record<string, Listener>>("listeners", "/listeners");
export const usePolicies = () =>
  useGet<Record<string, PluginConf>>("policies", "/policies");
export const useCertificates = () =>
  useGet<Record<string, CertificateView>>("ssl", "/ssl");
export const useWafCategories = () =>
  useGet<WafCategory[]>("waf-categories", "/waf/categories");
export const useWafEvents = (params = "") =>
  useGet<WafEventRecord[]>(`waf-events${params}`, `/logs/waf-events${params}`);
export const useAlertChannels = () =>
  useGet<NotificationChannel[]>("alert-channels", "/alerts/channels");
export const useAlertRules = () =>
  useGet<AlertRuleRecord[]>("alert-rules", "/alerts/rules");
export const useAlertHistory = (params = "") =>
  useGet<AlertHistory[]>(`alert-history${params}`, `/alerts/history${params}`);
export const useConfigVersions = () =>
  useGet<VersionView[]>("config-versions", "/config-versions");
export const useActivity = (params = "") =>
  useGet<Activity[]>(`activity${params}`, `/activity${params}`);
export const useNodes = () => useGet<NodeView[]>("nodes", "/nodes");
export const useBackup = () => useGet<BackupView>("backup", "/backup");
export const useUsers = () => useGet<UserView[]>("users", "/users");
export const useProfile = () => useGet<Profile>("account", "/account");
export const useSessions = () =>
  useGet<SessionView[]>("account-sessions", "/account/sessions");
export const useSecondFactor = () =>
  useGet<SecondFactorStatus>("account-2fa", "/account/2fa");

// ---- writes --------------------------------------------------------------------------

/** Invalidate the resource's key plus whatever a write necessarily changed. */
function useWriter(keys: string[]) {
  const qc = useQueryClient();
  return {
    invalidate: () => {
      for (const key of ["admin", ...keys]) {
        // Every config-shaped write produces a version and an activity row; every
        // mutation writes an activity row. Refresh those alongside the resource.
        for (const also of [key, "activity", "config-versions", "dashboard"]) {
          void qc.invalidateQueries({ queryKey: ["admin", also] });
        }
      }
    },
    qc,
  };
}

type Body = unknown;

function usePut<T>(keys: string[], build: (name: string) => string) {
  const { invalidate } = useWriter(keys);
  return useMutation({
    mutationFn: async ({ name, body }: { name: string; body: Body }) => {
      const res = await request.put<T>(build(name), body ?? {});
      return res.data;
    },
    onSettled: invalidate,
  });
}

function useDelete(keys: string[], build: (name: string) => string) {
  const { invalidate } = useWriter(keys);
  return useMutation({
    mutationFn: async (name: string) => {
      await request.delete(build(name));
    },
    onSettled: invalidate,
  });
}

function usePost<T = unknown, V = Body>(keys: string[], path: string) {
  const { invalidate } = useWriter(keys);
  return useMutation<T, Error, V>({
    mutationFn: async (body: V) => {
      const res = await request.post<T>(path, body ?? {});
      return res.data;
    },
    onSettled: invalidate,
  });
}

// Domains, upstreams, listeners, policies, certificates — the intent resources, all of
// which write through the projection and therefore produce a ConfigVersion on success.
export const usePutDomain = () =>
  usePut<Domain>(["domains"], (n) => `/domains/${encodeURIComponent(n)}`);
export const useDeleteDomain = () =>
  useDelete(["domains"], (n) => `/domains/${encodeURIComponent(n)}`);
export const usePutUpstream = () =>
  usePut<Upstream>(["upstreams"], (n) => `/upstreams/${encodeURIComponent(n)}`);
export const useDeleteUpstream = () =>
  useDelete(["upstreams"], (n) => `/upstreams/${encodeURIComponent(n)}`);
export const usePutListener = () =>
  usePut<Listener>(["listeners"], (n) => `/listeners/${encodeURIComponent(n)}`);
export const useDeleteListener = () =>
  useDelete(["listeners"], (n) => `/listeners/${encodeURIComponent(n)}`);
export const usePutPolicy = () =>
  usePut<PluginConf>(["policies"], (n) => `/policies/${encodeURIComponent(n)}`);
export const useDeletePolicy = () =>
  useDelete(["policies"], (n) => `/policies/${encodeURIComponent(n)}`);
export const usePutCertificate = () =>
  usePut<CertificateView>(["ssl"], (n) => `/ssl/${encodeURIComponent(n)}`);
export const useDeleteCertificate = () =>
  useDelete(["ssl"], (n) => `/ssl/${encodeURIComponent(n)}`);

// Alerts.
export const useCreateChannel = () =>
  usePost<NotificationChannel, Body>(["alert-channels"], "/alerts/channels");
export const useCreateRule = () =>
  usePost<AlertRuleRecord, Body>(["alert-rules"], "/alerts/rules");
export const useTestSend = () =>
  useMutation<{ delivered: boolean }, Error, string>({
    mutationFn: async (id) => {
      const res = await request.post<{ delivered: boolean }>(
        `/alerts/channels/${encodeURIComponent(id)}/test-send`,
        {},
      );
      return res.data;
    },
  });

// Config versions.
export const useRollback = () => {
  const { invalidate } = useWriter(["config-versions", "domains", "dashboard"]);
  return useMutation<RollbackResult, Error, string>({
    mutationFn: async (id) => {
      const res = await request.post<RollbackResult>(
        `/config-versions/${encodeURIComponent(id)}/rollback`,
        {},
      );
      return res.data;
    },
    onSettled: invalidate,
  });
};

// Backup.
export const useExportBackup = () =>
  usePost<BackupFileRecord, Body>(["backup"], "/backup/export");
export const useRestoreBackup = () =>
  usePost<unknown, { path: string }>(["backup"], "/backup/restore");
export const useCreateSchedule = () =>
  usePost<BackupScheduleRecord, Body>(["backup"], "/backup/schedules");
export const useDeleteSchedule = () =>
  useDelete(["backup"], (id) => `/backup/schedules/${encodeURIComponent(id)}`);

// Users (admin) + account (self-service).
export const useCreateUser = () =>
  usePost<UserView, Body>(["users"], "/users");
export const useUpdateUser = () =>
  useMutation<UserView, Error, { id: string; is_active: boolean }>({
    mutationFn: async ({ id, is_active }) => {
      const res = await request.patch<UserView>(
        `/users/${encodeURIComponent(id)}`,
        { is_active },
      );
      return res.data;
    },
    onSettled: useWriter(["users"]).invalidate,
  });
export const useResetUser2fa = () =>
  useMutation<unknown, Error, string>({
    mutationFn: async (id) => {
      await request.post(`/users/${encodeURIComponent(id)}/2fa/reset`, {});
    },
    onSettled: useWriter(["users"]).invalidate,
  });

export const useUpdateProfile = () =>
  useMutation<Profile, Error, { email: string }>({
    mutationFn: async (body) => {
      const res = await request.patch<Profile>("/account", body);
      return res.data;
    },
    onSettled: useWriter(["account"]).invalidate,
  });
export const useChangePassword = () =>
  usePost<{ sessions_revoked: number }, Body>(["account"], "/account/password");
export const useRevokeSession = () =>
  useDelete(["account-sessions"], (id) => `/account/sessions/${encodeURIComponent(id)}`);

export const useSetupSecondFactor = () =>
  usePost<SecondFactorSetup, Body>(["account-2fa"], "/account/2fa/setup");
export const useEnableSecondFactor = () =>
  usePost<unknown, { code: string }>(["account-2fa", "account"], "/account/2fa/enable");
export const useDisableSecondFactor = () =>
  usePost<unknown, { code: string }>(["account-2fa", "account"], "/account/2fa/disable");

// A config-version status is part of the projection contract; re-export for callers that
// branch on it rather than import twice.
export type { ConfigStatus };
