import { useI18n } from "@/i18n";
import {
  Card,
  CardContent,
  CardDescription,
  CardFooter,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Button } from "@/components/ui/button";
import React from "react";
import { LoginResult, removeLoginToken, saveLoginToken } from "@/states/token";
import useBasicState from "@/states/basic";
import { goToHome } from "@/routers";
import useConfigState from "@/states/config";
import { formatError } from "@/helpers/util";
import request from "@/helpers/request";
import { useShallow } from "zustand/react/shallow";
import { toast } from "sonner";
import Logo from "@/assets/pingap.png";
import { LoaderCircle } from "lucide-react";

export default function Login() {
  const loginI18n = useI18n("login");

  const [account, setAccount] = React.useState("");
  const [password, setPassword] = React.useState("");
  const [code, setCode] = React.useState("");
  // Set once the password is accepted but a second factor is outstanding.
  // The server decides this, not the form: it refuses every non-GET on a
  // password-only session, so there is nothing to bypass by skipping it.
  const [totpPending, setTotpPending] = React.useState(false);
  const [loading, setLoading] = React.useState(false);
  const [fetchBasicInfo] = useBasicState(useShallow((state) => [state.fetch]));
  const [fetchConfig] = useConfigState(useShallow((state) => [state.fetch]));

  const enter = async () => {
    await fetchBasicInfo();
    await fetchConfig();
    goToHome();
  };

  const handleLogin = async () => {
    if (loading) return;
    setLoading(true);
    try {
      const { data } = await request.post<LoginResult>("/auth/login", {
        username: account,
        password,
      });
      saveLoginToken(data.token);
      if (data.auth_level === "password_only") {
        setTotpPending(true);
        return;
      }
      await enter();
    } catch (err) {
      toast(loginI18n("fail"), {
        description: formatError(err),
      });
    } finally {
      setLoading(false);
    }
  };

  const handleTotp = async () => {
    if (loading) return;
    setLoading(true);
    try {
      await request.post("/auth/totp", { code });
      await enter();
    } catch (err) {
      // A refused code is 401, which the response interceptor treats as
      // "session gone" and clears the token. That is right for a stale
      // session and wrong here — the session is fine, the code was not — so
      // the form goes back to the start rather than leaving a half state.
      toast(loginI18n("totpFail"), {
        description: formatError(err),
      });
      removeLoginToken();
      setTotpPending(false);
      setCode("");
    } finally {
      setLoading(false);
    }
  };
  // Top aligned rather than centred, and high on the page: this route renders
  // without the app shell, so the 96px gap that used to line the card up under
  // the header is now the padding itself and the card lands in the same place.
  return (
    <div className="min-h-svh overflow-auto bg-background">
      <div className="mx-auto w-full max-w-[400px] px-4 pt-24 pb-10">
        <div className="mb-5 flex items-center gap-2.5">
          <span className="flex size-8 items-center justify-center rounded-md border border-border bg-card">
            <img src={Logo} alt="" className="size-5 rounded-sm" />
          </span>
          <span className="text-[15px] font-semibold tracking-tight">
            Pingap
          </span>
          <span className="eyebrow ml-0.5">admin</span>
        </div>
        {totpPending && (
          <Card className="w-full border-border">
            <CardHeader className="space-y-0 px-5 pt-5 pb-4">
              <CardTitle className="text-xl tracking-tight">
                {loginI18n("totpTitle")}
              </CardTitle>
              <CardDescription className="mt-1.5 text-[13px]">
                {loginI18n("totpDescription")}
              </CardDescription>
            </CardHeader>
            <CardContent className="space-y-4 px-5">
              <div className="space-y-2">
                <Label htmlFor="code">{loginI18n("totpCode")}</Label>
                <Input
                  id="code"
                  autoFocus
                  autoComplete="one-time-code"
                  inputMode="numeric"
                  maxLength={6}
                  className="machine h-10"
                  value={code}
                  onChange={(e) => {
                    setCode(e.target.value.trim());
                  }}
                  onKeyDown={(e) => {
                    if (e.code == "Enter") {
                      handleTotp();
                    }
                  }}
                />
              </div>
            </CardContent>
            <CardFooter className="px-5 pt-5 pb-5">
              <Button
                className="h-10 w-full cursor-pointer"
                disabled={loading || code.length < 6}
                onClick={(e) => {
                  e.preventDefault();
                  handleTotp();
                }}
              >
                {loading && (
                  <LoaderCircle className="mr-2 size-4 animate-spin" />
                )}
                {loginI18n("totpSubmit")}
              </Button>
            </CardFooter>
          </Card>
        )}
        {!totpPending && (
          <Card className="w-full border-border">
            <CardHeader className="space-y-0 px-5 pt-5 pb-4">
              <CardTitle className="text-xl tracking-tight">
                {loginI18n("title")}
              </CardTitle>
              <CardDescription className="mt-1.5 text-[13px]">
                {loginI18n("description")}
              </CardDescription>
            </CardHeader>
            <CardContent className="space-y-4 px-5">
              <div className="space-y-2">
                <Label htmlFor="account">{loginI18n("account")}</Label>
                <Input
                  id="account"
                  autoFocus
                  autoComplete="username"
                  className="machine h-10"
                  onChange={(e) => {
                    setAccount(e.target.value.trim());
                  }}
                />
              </div>
              <div className="space-y-2">
                <Label htmlFor="password">{loginI18n("password")}</Label>
                <Input
                  id="password"
                  type="password"
                  autoComplete="current-password"
                  className="machine h-10"
                  onChange={(e) => {
                    setPassword(e.target.value.trim());
                  }}
                  onKeyDown={(e) => {
                    if (e.code == "Enter") {
                      handleLogin();
                    }
                  }}
                />
              </div>
            </CardContent>
            <CardFooter className="px-5 pt-5 pb-5">
              <Button
                className="h-10 w-full cursor-pointer"
                disabled={loading || !account || !password}
                onClick={(e) => {
                  e.preventDefault();
                  handleLogin();
                }}
              >
                {loading && (
                  <LoaderCircle className="mr-2 size-4 animate-spin" />
                )}
                {loginI18n("submit")}
              </Button>
            </CardFooter>
          </Card>
        )}
      </div>
    </div>
  );
}
