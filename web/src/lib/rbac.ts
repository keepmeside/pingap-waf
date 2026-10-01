import { getLoginToken } from "@/states/token";
import type { Capability, Profile, Role } from "@/lib/types";

export type { Role };

/**
 * The role, decoded off the bearer token's claims.
 *
 * Useful only for coarse display ("signed in as admin"). For whether a control may be
 * used at all, prefer `can()` against the server's capability list: a password-only
 * session has a role but not yet the full capability set, and decoding the role alone
 * would show controls that currently 403.
 */
export function getRole(): Role {
  const token = getLoginToken();
  try {
    const payload = token.split(".")[1];
    if (!payload) return "viewer";
    const value = JSON.parse(atob(payload)) as { role?: Role };
    return value.role === "admin" || value.role === "operator" ? value.role : "viewer";
  } catch {
    return "viewer";
  }
}

export function canMutate(role: Role = getRole()): boolean {
  return role === "admin" || role === "operator";
}

export function isAdmin(role: Role = getRole()): boolean {
  return role === "admin";
}

/**
 * Whether the server's capability list contains `capability`.
 *
 * The list is the one `/account` returns, derived on the server from the caller's role
 * *and* auth level — so a session that has not completed its second factor is told the
 * read capabilities it actually has, and the UI can shrink to match. The list can be too
 * short (a control hidden until the operator confirms) but never too long (a control
 * shown that the gate will refuse).
 *
 * The server remains the enforcement; this only decides which affordances to render.
 * Passing no profile — the query has not returned yet — answers `false`, so a control
 * appears only once the server has said it is usable, never optimistically.
 */
export function can(profile: Profile | null | undefined, capability: Capability): boolean {
  if (!profile) return false;
  return profile.capabilities.includes(capability);
}

/** Whether the caller holds any of the named capabilities — for a control valid under
 * several (e.g. an edit reachable by more than one capability). */
export function canAny(profile: Profile | null | undefined, capabilities: Capability[]): boolean {
  return capabilities.some((capability) => can(profile, capability));
}
