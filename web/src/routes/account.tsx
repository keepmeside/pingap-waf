import React from "react";
import { PageShell } from "@/components/page-shell";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import {
  EmptyState, ErrorNote, FieldList, FieldRow, LoadingCard,
} from "@/components/data-ui";
import { ConfirmDialog } from "@/components/confirm-dialog";
import {
  useChangePassword, useDisableSecondFactor, useEnableSecondFactor, useProfile,
  useRevokeSession, useSecondFactor, useSessions, useSetupSecondFactor,
  useUpdateProfile,
} from "@/queries/admin";
import { can } from "@/lib/rbac";
import { fmtTime, orDash } from "@/lib/format";
import { formatError } from "@/helpers/util";
import { toast } from "sonner";
import type { Profile, SessionView } from "@/lib/types";
import { KeyRound, LogOut, MonitorSmartphone, ShieldCheck, ShieldOff, UserRound } from "lucide-react";

/**
 * The signed-in account's self-service page — what it must never get wrong:
 *
 * - Every mutating control keys off the server's capability list, not the role name:
 *   a password-only session is a real session with a shrunken capability set, and the
 *   UI must shrink to match instead of offering buttons that 403.
 * - Revoking the *current* session signs this browser out mid-action; the typed confirm
 *   names that case explicitly rather than treating all sessions alike.
 * - The TOTP `secret`/`otpauth_uri` exists on screen exactly once — the response to the
 *   setup call, which the API will not repeat. It lives in component state, is never
 *   re-rendered after enable succeeds, and is cleared from state the moment enrolment
 *   completes.
 */
export default function Account() {
  const profileQuery = useProfile();
  const profile = profileQuery.data?.data ?? null;

  return (
    <PageShell
      title="Account"
      eyebrow="Account · self-service"
      description="Your console identity: profile, live sessions, password and second factor. Mutating controls follow the capability list this session actually holds."
      width="narrow"
    >
      {profileQuery.isPending ? (
        <LoadingCard />
      ) : profileQuery.isError ? (
        <ErrorNote message={formatError(profileQuery.error)} />
      ) : !profile || profileQuery.data.unavailable ? (
        <EmptyState
          title="Account endpoint unavailable"
          hint="The connected server does not expose /account."
        />
      ) : (
        <div className="space-y-4">
          <ProfileCard profile={profile} />
          <SessionsCard profile={profile} />
          <PasswordCard profile={profile} />
          <SecondFactorCard profile={profile} />
        </div>
      )}
    </PageShell>
  );
}

/** Identity fields plus the one editable one — email — gated on `edit_own_profile`.
 * Capabilities render as badges: they are what the server granted, so they are the
 * page's own legend for why controls elsewhere are present or hidden. */
function ProfileCard({ profile }: { profile: Profile }) {
  const updateProfile = useUpdateProfile();
  const [editing, setEditing] = React.useState(false);
  const [email, setEmail] = React.useState(profile.email);
  const canEdit = can(profile, "edit_own_profile");

  return (
    <Card>
      <CardHeader>
        <CardTitle className="flex items-center gap-2 text-base">
          <UserRound className="size-4" /> Profile
        </CardTitle>
        <CardDescription>
          Who this session is. Email is the only field you can change here.
        </CardDescription>
      </CardHeader>
      <CardContent>
        <FieldList>
          <FieldRow label="Username">{profile.username}</FieldRow>
          <FieldRow label="Email">
            {editing ? (
              <div className="flex items-center gap-2">
                <Input
                  type="email"
                  autoComplete="email"
                  value={email}
                  onChange={(e) => setEmail(e.target.value)}
                  className="max-w-xs"
                />
                <Button
                  size="sm"
                  disabled={updateProfile.isPending}
                  onClick={() =>
                    updateProfile.mutate(
                      { email: email.trim() },
                      {
                        onSuccess: () => {
                          toast.success("Profile updated");
                          setEditing(false);
                        },
                        onError: (e) =>
                          toast.error("Update failed", { description: formatError(e) }),
                      },
                    )
                  }
                >
                  {updateProfile.isPending ? "Saving…" : "Save"}
                </Button>
                <Button
                  size="sm"
                  variant="ghost"
                  onClick={() => {
                    setEditing(false);
                    setEmail(profile.email);
                  }}
                >
                  Cancel
                </Button>
              </div>
            ) : (
              <span className="flex items-center gap-2">
                {orDash(profile.email)}
                {canEdit && (
                  <Button size="sm" variant="ghost" onClick={() => setEditing(true)}>
                    Edit
                  </Button>
                )}
              </span>
            )}
          </FieldRow>
          <FieldRow label="Role">
            <Badge variant="outline" className="machine uppercase">
              {profile.role}
            </Badge>
          </FieldRow>
          <FieldRow label="Auth level">
            <Badge variant="secondary" className="machine">
              {profile.auth_level}
            </Badge>
          </FieldRow>
          <FieldRow label="Status">{profile.is_active ? "active" : "suspended"}</FieldRow>
          <FieldRow label="Capabilities">
            <div className="flex flex-wrap gap-1.5">
              {profile.capabilities.map((capability) => (
                <Badge key={capability} variant="outline" className="machine text-[11px]">
                  {capability}
                </Badge>
              ))}
            </div>
          </FieldRow>
        </FieldList>
      </CardContent>
    </Card>
  );
}

/** Live sessions for this account. Revoking any but the current one signs that device
 * out; revoking `current` ends this browser's session at once, so the confirm text
 * names the case rather than a generic id. */
function SessionsCard({ profile }: { profile: Profile }) {
  const sessions = useSessions();
  const revokeSession = useRevokeSession();
  const [target, setTarget] = React.useState<SessionView | null>(null);
  const canRevoke = can(profile, "revoke_own_session");

  return (
    <Card>
      <CardHeader>
        <CardTitle className="flex items-center gap-2 text-base">
          <MonitorSmartphone className="size-4" /> Sessions
        </CardTitle>
        <CardDescription>
          Signed-in sessions for this account. Revoke signs that session out; the one
          marked current is this browser.
        </CardDescription>
      </CardHeader>
      <CardContent>
        {sessions.isPending ? (
          <p className="py-4 text-xs text-muted-foreground">Loading sessions…</p>
        ) : sessions.isError ? (
          <ErrorNote message={formatError(sessions.error)} />
        ) : sessions.data.unavailable ? (
          <EmptyState title="Sessions unavailable" hint={sessions.data.message} />
        ) : (sessions.data.data ?? []).length === 0 ? (
          <EmptyState title="No sessions" hint="The connected server returned no session records." />
        ) : (
          <ul className="divide-y divide-border/60">
            {(sessions.data.data ?? []).map((session) => (
              <li key={session.id} className="flex flex-wrap items-center gap-x-3 gap-y-1 py-2.5">
                <div className="min-w-0 flex-1">
                  <div className="flex flex-wrap items-center gap-2">
                    <span className="machine truncate text-sm">
                      {orDash(session.user_agent)}
                    </span>
                    {session.current && (
                      <Badge variant="secondary" className="text-[11px]">
                        current
                      </Badge>
                    )}
                    {!session.usable && (
                      <Badge variant="outline" className="text-[11px] text-muted-foreground">
                        not usable
                      </Badge>
                    )}
                  </div>
                  <div className="mt-0.5 flex flex-wrap gap-x-3 text-xs text-muted-foreground">
                    <span className="machine">{session.auth_level}</span>
                    <span>{orDash(session.ip)}</span>
                    <span>expires {fmtTime(session.expires_at)}</span>
                  </div>
                </div>
                {canRevoke && session.usable && (
                  <Button
                    size="sm"
                    variant="ghost"
                    onClick={() => setTarget(session)}
                  >
                    <LogOut className="size-4" /> Revoke
                  </Button>
                )}
              </li>
            ))}
          </ul>
        )}
      </CardContent>

      <ConfirmDialog
        open={target !== null}
        onOpenChange={(open) => !open && setTarget(null)}
        title={target?.current ? "Revoke this session?" : "Revoke session?"}
        description={
          target?.current ? (
            <p>
              This is your <span className="font-medium">current</span> session —
              confirming signs this browser out immediately and you will need to sign in
              again.
            </p>
          ) : (
            <p>
              The session on <span className="machine">{orDash(target?.user_agent)}</span>{" "}
              ({orDash(target?.ip)}) is signed out at once and its token stops working.
            </p>
          )
        }
        confirmText={target?.current ? "current" : "revoke"}
        confirmLabel="Revoke session"
        busy={revokeSession.isPending}
        onConfirm={() => {
          if (!target) return;
          revokeSession.mutate(target.id, {
            onSuccess: () => {
              toast.success("Session revoked");
              setTarget(null);
            },
            onError: (e) =>
              toast.error("Revoke failed", { description: formatError(e) }),
          });
        }}
      />
    </Card>
  );
}

/** Password change. The server returns `sessions_revoked` — how many other sessions the
 * change invalidated — shown in the success toast so the operator sees the blast radius
 * of what they just did. */
function PasswordCard({ profile }: { profile: Profile }) {
  const changePassword = useChangePassword();
  const [currentPassword, setCurrentPassword] = React.useState("");
  const [newPassword, setNewPassword] = React.useState("");
  const canChange = can(profile, "change_own_password");

  const submit = () => {
    if (!currentPassword || !newPassword) {
      toast.error("Both password fields are required");
      return;
    }
    changePassword.mutate(
      { current_password: currentPassword, new_password: newPassword },
      {
        onSuccess: (data) => {
          toast.success("Password changed", {
            description:
              data.sessions_revoked > 0
                ? `${data.sessions_revoked} other session${data.sessions_revoked === 1 ? "" : "s"} revoked`
                : "No other sessions were active",
          });
          setCurrentPassword("");
          setNewPassword("");
        },
        onError: (e) =>
          toast.error("Change failed", { description: formatError(e) }),
      },
    );
  };

  return (
    <Card>
      <CardHeader>
        <CardTitle className="flex items-center gap-2 text-base">
          <KeyRound className="size-4" /> Password
        </CardTitle>
        <CardDescription>
          Changing the password revokes your other sessions. This one keeps working.
        </CardDescription>
      </CardHeader>
      <CardContent>
        {canChange ? (
          <div className="grid max-w-sm gap-3">
            <div className="grid gap-1.5">
              <Label htmlFor="account-current-password">Current password</Label>
              <Input
                id="account-current-password"
                type="password"
                autoComplete="current-password"
                value={currentPassword}
                onChange={(e) => setCurrentPassword(e.target.value)}
              />
            </div>
            <div className="grid gap-1.5">
              <Label htmlFor="account-new-password">New password</Label>
              <Input
                id="account-new-password"
                type="password"
                autoComplete="new-password"
                value={newPassword}
                onChange={(e) => setNewPassword(e.target.value)}
              />
            </div>
            <div>
              <Button size="sm" onClick={submit} disabled={changePassword.isPending}>
                {changePassword.isPending ? "Changing…" : "Change password"}
              </Button>
            </div>
          </div>
        ) : (
          <p className="text-xs text-muted-foreground">
            This session cannot change the password — a second factor may be required.
          </p>
        )}
      </CardContent>
    </Card>
  );
}

/** TOTP enrolment, in the three states the API reports:
 *
 * - not enabled → "Set up" calls `/account/2fa/setup` and shows `secret` +
 *   `otpauth_uri` exactly once. The response is the only time the secret ever leaves
 *   the server; it is kept in local state and dropped as soon as enable succeeds.
 * - setup shown → a code input verifies the authenticator was added before the server
 *   flips `enabled` on, so an operator cannot lock themselves out with a typo'd secret.
 * - enabled → disable requires a live code plus typed confirmation.
 */
function SecondFactorCard({ profile }: { profile: Profile }) {
  const secondFactor = useSecondFactor();
  const setup = useSetupSecondFactor();
  const enable = useEnableSecondFactor();
  const disable = useDisableSecondFactor();
  const canManage = can(profile, "manage_own_second_factor");

  const [setupData, setSetupData] = React.useState<{
    secret: string;
    otpauth_uri: string;
  } | null>(null);
  const [code, setCode] = React.useState("");
  const [disableOpen, setDisableOpen] = React.useState(false);
  const [disableCode, setDisableCode] = React.useState("");

  const status = secondFactor.data;
  const enabled = status?.data?.enabled ?? false;

  const startSetup = () =>
    setup.mutate(undefined, {
      onSuccess: (data) => setSetupData(data),
      onError: (e) =>
        toast.error("Setup failed", { description: formatError(e) }),
    });

  const confirmEnable = () => {
    if (!code.trim()) {
      toast.error("Enter the code from your authenticator");
      return;
    }
    enable.mutate(
      { code: code.trim() },
      {
        onSuccess: () => {
          toast.success("Two-factor enabled");
          setSetupData(null);
          setCode("");
        },
        onError: (e) =>
          toast.error("Enable failed", { description: formatError(e) }),
      },
    );
  };

  return (
    <Card>
      <CardHeader>
        <CardTitle className="flex items-center gap-2 text-base">
          <ShieldCheck className="size-4" /> Two-factor
        </CardTitle>
        <CardDescription>
          A TOTP second factor. Mutating account actions may require the
          {" "}
          <span className="machine">two_factor</span> auth level it grants.
        </CardDescription>
      </CardHeader>
      <CardContent>
        {!canManage ? (
          <p className="text-xs text-muted-foreground">
            This session cannot manage two-factor enrolment.
          </p>
        ) : secondFactor.isPending ? (
          <p className="py-4 text-xs text-muted-foreground">Loading two-factor status…</p>
        ) : secondFactor.isError ? (
          <ErrorNote message={formatError(secondFactor.error)} />
        ) : status?.unavailable ? (
          <EmptyState title="Two-factor unavailable" hint={status.message} />
        ) : enabled ? (
          <div className="space-y-3">
            <p className="text-sm">
              Two-factor is <span className="font-medium">enabled</span> for this account.
            </p>
            <Button size="sm" variant="outline" onClick={() => setDisableOpen(true)}>
              <ShieldOff className="size-4" /> Disable two-factor
            </Button>
          </div>
        ) : setupData ? (
          <div className="max-w-md space-y-4">
            <div className="rounded-md border border-amber-500/40 bg-amber-500/5 px-3 py-2.5">
              <p className="text-xs font-medium text-amber-700 dark:text-amber-400">
                Add this secret to your authenticator now — it is shown once and cannot
                be retrieved again.
              </p>
            </div>
            <FieldList>
              <FieldRow label="Secret">
                <code className="machine break-all text-xs">{setupData.secret}</code>
              </FieldRow>
              <FieldRow label="otpauth URI">
                <code className="machine break-all text-xs">{setupData.otpauth_uri}</code>
              </FieldRow>
            </FieldList>
            <div className="grid gap-1.5">
              <Label htmlFor="account-2fa-code">Authenticator code</Label>
              <div className="flex items-center gap-2">
                <Input
                  id="account-2fa-code"
                  inputMode="numeric"
                  autoComplete="one-time-code"
                  placeholder="123456"
                  value={code}
                  onChange={(e) => setCode(e.target.value)}
                  className="machine w-40"
                />
                <Button size="sm" onClick={confirmEnable} disabled={enable.isPending}>
                  {enable.isPending ? "Verifying…" : "Enable"}
                </Button>
              </div>
            </div>
          </div>
        ) : (
          <div className="space-y-3">
            <p className="text-sm">
              Two-factor is <span className="font-medium">not enabled</span>
              {status?.data?.enrolled ? " — a secret is enrolled but not yet active" : ""}.
            </p>
            <Button size="sm" variant="outline" onClick={startSetup} disabled={setup.isPending}>
              <ShieldCheck className="size-4" />
              {setup.isPending ? "Preparing…" : "Set up two-factor"}
            </Button>
          </div>
        )}
      </CardContent>

      <ConfirmDialog
        open={disableOpen}
        onOpenChange={setDisableOpen}
        title="Disable two-factor?"
        description={
          <div className="space-y-3">
            <p>
              Sign-in drops back to password only, and capabilities that require the{" "}
              <span className="machine">two_factor</span> auth level stop being granted
              until you re-enrol.
            </p>
            <div className="grid gap-1.5">
              <Label htmlFor="account-2fa-disable-code" className="text-xs">
                Current authenticator code
              </Label>
              <Input
                id="account-2fa-disable-code"
                inputMode="numeric"
                autoComplete="one-time-code"
                placeholder="123456"
                value={disableCode}
                onChange={(e) => setDisableCode(e.target.value)}
                className="machine"
              />
            </div>
          </div>
        }
        confirmText="disable"
        confirmLabel="Disable 2FA"
        busy={disable.isPending}
        onConfirm={() => {
          disable.mutate(
            { code: disableCode.trim() },
            {
              onSuccess: () => {
                toast.success("Two-factor disabled");
                setDisableOpen(false);
                setDisableCode("");
              },
              onError: (e) =>
                toast.error("Disable failed", { description: formatError(e) }),
            },
          );
        }}
      />
    </Card>
  );
}
