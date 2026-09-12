const PINGAP_LOGIN_TOKEN = "pingap:loginToken";

// What /api/auth/login answers. `auth_level` is "password_only" while a
// second factor is still outstanding; the server refuses every non-GET until
// it is completed.
export interface LoginResult {
  token: string;
  auth_level: "password_only" | "two_factor";
  role: "admin" | "operator" | "viewer";
  username: string;
}

// The bearer token the server issued. The password never touches storage:
// the server hashes it, and what the browser holds is something the server
// can revoke.
export function saveLoginToken(token: string) {
  window.localStorage.setItem(PINGAP_LOGIN_TOKEN, token);
}

export function getLoginToken() {
  return window.localStorage.getItem(PINGAP_LOGIN_TOKEN) || "";
}

export function removeLoginToken() {
  window.localStorage.removeItem(PINGAP_LOGIN_TOKEN);
}
