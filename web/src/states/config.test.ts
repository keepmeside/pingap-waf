const session = vi.hoisted(() => ({ token: "initial" }));
vi.mock("@/states/token", () => ({ getLoginToken: () => session.token }));
import { beforeEach, expect, it, vi } from "vitest";
vi.mock("@/helpers/request", () => ({ default: { get: vi.fn() } }));
import request from "@/helpers/request";
import useConfigState from "./config";
const get = vi.mocked(request.get);
beforeEach(() => {
  vi.resetAllMocks();
  session.token = "initial";
  useConfigState.setState({
    data: {
      basic: useConfigState.getInitialState().data.basic,
      plugins: { previous: { category: "fixture" } },
    },
    initialized: false,
    fullToml: "old privileged data",
    originalToml: "old privileged data",
    hcl: "old privileged data",
  });
});
it("viewer initializes without reading raw config and clears previous privileged cache", async () => {
  get.mockResolvedValueOnce({
    data: { capabilities: ["view_config", "view_logs"] },
  });
  const value = await useConfigState.getState().fetch();
  expect(get.mock.calls.map((c) => c[0])).toEqual(["/account"]);
  expect(value).toEqual({ basic: {} });
  expect(useConfigState.getState()).toMatchObject({
    initialized: true,
    fullToml: "",
    originalToml: "",
    hcl: "",
  });
});
it("raw config permission retains the complete fetch", async () => {
  const conf = {
    basic: { name: "canary" },
    plugins: { strict: { category: "waf", future_field: 7 } },
  };
  get
    .mockResolvedValueOnce({ data: { capabilities: ["view_raw_config"] } })
    .mockResolvedValueOnce({ data: conf });
  expect(await useConfigState.getState().fetch()).toEqual(conf);
  expect(get.mock.calls.map((c) => c[0])).toEqual(["/account", "/configs"]);
});
it("does not turn unavailable privileged configuration into an empty success", async () => {
  get
    .mockResolvedValueOnce({ data: { capabilities: ["view_raw_config"] } })
    .mockRejectedValueOnce({ status: 503 });
  await expect(useConfigState.getState().fetch()).rejects.toMatchObject({
    status: 503,
  });
  expect(useConfigState.getState().initialized).toBe(false);
});

it("clears privileged cache on account-read failure and still reports the failure", async () => {
  get.mockRejectedValueOnce({ status: 401 });
  await expect(useConfigState.getState().fetch()).rejects.toMatchObject({
    status: 401,
  });
  expect(useConfigState.getState()).toMatchObject({
    data: { basic: {} },
    initialized: false,
    fullToml: "",
    originalToml: "",
    hcl: "",
  });
});

it("does not publish an old raw response after the account changes", async () => {
  let finish: (value: unknown) => void = () => {};
  get
    .mockResolvedValueOnce({ data: { capabilities: ["view_raw_config"] } })
    .mockImplementationOnce(
      () =>
        new Promise((resolve) => {
          finish = resolve;
        }),
    );
  const pending = useConfigState.getState().fetch();
  await vi.waitFor(() => expect(get).toHaveBeenCalledTimes(2));
  session.token = "new-session";
  useConfigState.setState({
    data: { basic: useConfigState.getInitialState().data.basic },
    fullToml: "",
    originalToml: "",
    hcl: "",
  });
  finish({ data: { basic: { name: "old-account-private" } } });
  await expect(pending).rejects.toThrow(/session/i);
  expect(useConfigState.getState().data).toEqual({ basic: {} });
});
it("does not publish old full-config text after logout", async () => {
  let finish: (value: unknown) => void = () => {};
  get.mockImplementationOnce(
    () =>
      new Promise((resolve) => {
        finish = resolve;
      }),
  );
  const pending = useConfigState.getState().fetchFullConfig();
  session.token = "";
  useConfigState.setState({ fullToml: "", originalToml: "", hcl: "" });
  finish({
    data: { full: "old-full", original: "old-original", hcl: "old-hcl" },
  });
  await expect(pending).rejects.toThrow(/session/i);
  expect(useConfigState.getState()).toMatchObject({
    fullToml: "",
    originalToml: "",
    hcl: "",
  });
});
