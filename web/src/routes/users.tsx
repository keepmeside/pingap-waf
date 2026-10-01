import React from "react";
import { PageShell } from "@/components/page-shell";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Switch } from "@/components/ui/switch";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import {
  Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle,
} from "@/components/ui/dialog";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { EmptyState, ErrorNote, LoadingCard } from "@/components/data-ui";
import { ConfirmDialog } from "@/components/confirm-dialog";
import {
  useCreateUser, useProfile, useResetUser2fa, useUpdateUser, useUsers,
} from "@/queries/admin";
import { can } from "@/lib/rbac";
import { fmtTime } from "@/lib/format";
import { formatError } from "@/helpers/util";
import { toast } from "sonner";
import type { Role, UserView } from "@/lib/types";
import { Plus, ShieldOff } from "lucide-react";

const ROLES: Role[] = ["admin", "operator", "viewer"];

/**
 * Admin user management. What it must never get wrong:
 *
 * - `manage_users` is the only capability that touches another person's account; without
 *   it the page is a read-only roster — no create dialog, no activate toggle, no 2FA
 *   reset. The roster itself still renders: a non-admin who lands here sees what the
 *   endpoint returns rather than a crash.
 * - "Reset 2FA" clears *someone else's* second factor — the recovery path for a
 *   locked-out user, and the action an attacker with admin session would reach for.
 *   Typed-confirm naming the username is what makes it a decision, not a reflex.
 * - Deactivation is a switch, not a confirm: it is reversible by the same switch.
 */
export default function Users() {
  const profileQuery = useProfile();
  const users = useUsers();
  const updateUser = useUpdateUser();
  const reset2fa = useResetUser2fa();
  const [creating, setCreating] = React.useState(false);
  const [resetTarget, setResetTarget] = React.useState<UserView | null>(null);
  const canManage = can(profileQuery.data?.data, "manage_users");

  return (
    <PageShell
      title="Users"
      eyebrow="Admin · users"
      description="Console accounts. Deactivation suspends sign-in without deleting history; a 2FA reset clears the user's second factor so they can re-enrol at next login."
      actions={
        canManage && (
          <Button size="sm" onClick={() => setCreating(true)}>
            <Plus className="size-4" /> New user
          </Button>
        )
      }
    >
      {users.isPending ? (
        <LoadingCard />
      ) : users.isError ? (
        <ErrorNote message={formatError(users.error)} />
      ) : users.data.unavailable ? (
        <EmptyState
          title="User management unavailable"
          hint={users.data.message}
        />
      ) : (
        <Card>
          <CardHeader>
            <CardTitle className="text-base">Accounts</CardTitle>
            <CardDescription>
              Every account that can sign in to this console. The role selects the
              capability set the server grants on login.
            </CardDescription>
          </CardHeader>
          <CardContent>
            {(users.data.data ?? []).length === 0 ? (
              <EmptyState title="No users" hint="The connected server returned an empty account list." />
            ) : (
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead>Username</TableHead>
                    <TableHead>Email</TableHead>
                    <TableHead>Role</TableHead>
                    <TableHead>Created</TableHead>
                    {canManage && <TableHead>Active</TableHead>}
                    {canManage && <TableHead className="text-right">Actions</TableHead>}
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {(users.data.data ?? []).map((user) => (
                    <TableRow key={user.id}>
                      <TableCell className="font-medium">{user.username}</TableCell>
                      <TableCell>{user.email || "—"}</TableCell>
                      <TableCell>
                        <Badge variant="outline" className="machine uppercase">
                          {user.role}
                        </Badge>
                      </TableCell>
                      <TableCell className="text-muted-foreground">
                        {fmtTime(user.created_at)}
                      </TableCell>
                      {canManage && (
                        <TableCell>
                          <Switch
                            checked={user.is_active}
                            aria-label={`${user.is_active ? "Deactivate" : "Activate"} ${user.username}`}
                            onCheckedChange={(checked) =>
                              updateUser.mutate(
                                { id: user.id, is_active: checked },
                                {
                                  onError: (e) =>
                                    toast.error("Update failed", {
                                      description: formatError(e),
                                    }),
                                },
                              )
                            }
                          />
                        </TableCell>
                      )}
                      {canManage && (
                        <TableCell className="text-right">
                          <Button
                            size="sm"
                            variant="ghost"
                            onClick={() => setResetTarget(user)}
                          >
                            <ShieldOff className="size-4" /> Reset 2FA
                          </Button>
                        </TableCell>
                      )}
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            )}
          </CardContent>
        </Card>
      )}

      <NewUserDialog open={creating} onOpenChange={setCreating} />

      <ConfirmDialog
        open={resetTarget !== null}
        onOpenChange={(open) => !open && setResetTarget(null)}
        title={`Reset 2FA for ${resetTarget?.username ?? ""}?`}
        description={
          <p>
            This clears the second factor enrolled on <span className="font-medium">{resetTarget?.username}</span>.
            Their next sign-in succeeds with password only until they enrol a new one —
            the recovery path for a user locked out of their authenticator.
          </p>
        }
        confirmText={resetTarget?.username ?? ""}
        confirmLabel="Reset 2FA"
        busy={reset2fa.isPending}
        onConfirm={() => {
          if (!resetTarget) return;
          reset2fa.mutate(resetTarget.id, {
            onSuccess: () => {
              toast.success(`2FA reset for ${resetTarget.username}`);
              setResetTarget(null);
            },
            onError: (e) =>
              toast.error("Reset failed", { description: formatError(e) }),
          });
        }}
      />
    </PageShell>
  );
}

/**
 * The create-account dialog. The password is sent on create and held only in the
 * dialog's input state — never rendered back, never persisted. Role is the server's
 * capability bundle: admin, operator, viewer.
 */
function NewUserDialog({
  open,
  onOpenChange,
}: {
  open: boolean;
  onOpenChange: (open: boolean) => void;
}) {
  const createUser = useCreateUser();
  const [username, setUsername] = React.useState("");
  const [email, setEmail] = React.useState("");
  const [password, setPassword] = React.useState("");
  const [role, setRole] = React.useState<Role>("viewer");

  React.useEffect(() => {
    if (!open) {
      setUsername("");
      setEmail("");
      setPassword("");
      setRole("viewer");
    }
  }, [open]);

  const submit = () => {
    if (!username.trim() || !password) {
      toast.error("Username and password are required");
      return;
    }
    createUser.mutate(
      { username: username.trim(), email: email.trim(), password, role },
      {
        onSuccess: () => {
          toast.success(`User ${username.trim()} created`);
          onOpenChange(false);
        },
        onError: (e) =>
          toast.error("Create failed", { description: formatError(e) }),
      },
    );
  };

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent>
        <DialogHeader>
          <DialogTitle>New user</DialogTitle>
          <DialogDescription>
            The account signs in with this password; the role selects which console
            capabilities the server grants.
          </DialogDescription>
        </DialogHeader>
        <div className="grid gap-3">
          <div className="grid gap-1.5">
            <Label htmlFor="new-user-name">Username</Label>
            <Input
              id="new-user-name"
              autoComplete="off"
              value={username}
              onChange={(e) => setUsername(e.target.value)}
            />
          </div>
          <div className="grid gap-1.5">
            <Label htmlFor="new-user-email">Email</Label>
            <Input
              id="new-user-email"
              type="email"
              autoComplete="off"
              value={email}
              onChange={(e) => setEmail(e.target.value)}
            />
          </div>
          <div className="grid gap-1.5">
            <Label htmlFor="new-user-password">Password</Label>
            <Input
              id="new-user-password"
              type="password"
              autoComplete="new-password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
            />
          </div>
          <div className="grid gap-1.5">
            <Label htmlFor="new-user-role">Role</Label>
            <Select value={role} onValueChange={(v) => setRole(v as Role)}>
              <SelectTrigger id="new-user-role">
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                {ROLES.map((r) => (
                  <SelectItem key={r} value={r}>
                    {r}
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
          </div>
        </div>
        <DialogFooter>
          <Button variant="ghost" onClick={() => onOpenChange(false)}>
            Cancel
          </Button>
          <Button onClick={submit} disabled={createUser.isPending}>
            {createUser.isPending ? "Creating…" : "Create user"}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}
