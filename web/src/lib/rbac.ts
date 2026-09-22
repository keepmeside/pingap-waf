import { getLoginToken } from "@/states/token";

export type Role = "admin" | "operator" | "viewer";

/** The server remains authoritative; this only controls which affordances are shown. */
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
