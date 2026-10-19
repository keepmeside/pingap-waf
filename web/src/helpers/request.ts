import axios, { AxiosRequestConfig, AxiosResponse } from "axios";
import HTTPError from "./http-error";
import { apiErrorMessage } from "./api-error";

import { getLoginToken, removeLoginToken } from "@/states/token";

const requestedAt = "X-Requested-At";
const request = axios.create({
  // 默认超时为10秒
  timeout: 10 * 1000,
});

request.interceptors.request.use(
  (config) => {
    const token = getLoginToken();
    if (token) {
      config.headers["Authorization"] = `Bearer ${token}`;
    }
    // 对请求的query部分清空值
    if (config.params) {
      Object.keys(config.params).forEach((element) => {
        // 空字符
        if (config.params[element] === "") {
          delete config.params[element];
        }
      });
    }
    config.url = `./api${config.url}`;
    if (config.headers) {
      config.headers[requestedAt] = `${Date.now()}`;
    }
    return config;
  },
  (err) => {
    return Promise.reject(err);
  },
);

// addRequestStats 添加http请求的相关记录
function addRequestStats(
  config: AxiosRequestConfig | undefined,
  res: AxiosResponse | undefined,
  he: HTTPError | undefined,
): void {
  const data: Record<string, unknown> = {};
  if (config) {
    data.method = config.method;
    data.url = config.url;
    data.data = config.data;
    if (config.headers) {
      const value = config.headers[requestedAt];
      data.use = Date.now() - Number(value);
    }
  }
  if (res) {
    data.status = res.status;
  }
  if (he) {
    data.message = he.message;
  }
  // httpRequests.add(data);
}

// 设置接口最少要x ms才完成，能让客户看到loading
const minUse = 300;
const timeoutErrorCodes = [
  "ECONNABORTED",
  "ETIMEDOUT",
  "ECONNREFUSED",
  "ECONNRESET",
];
request.interceptors.response.use(
  async (res) => {
    addRequestStats(res.config, res, undefined);
    // 根据请求开始时间计算耗时，并判断是否需要延时响应
    if (res.config.method != "get" && res.config.headers) {
      const value = res.config.headers[requestedAt];
      if (value) {
        const use = Date.now() - Number(value);
        if (use >= 0 && use < minUse) {
          await new Promise((resolve) => setTimeout(resolve, minUse - use));
        }
      }
    }
    return res;
  },
  (err) => {
    const { response } = err;

    const he = new HTTPError("Unknown error");
    // Axios network failures have no response — guard before reading status.
    he.status = response?.status ?? 0;
    const authorization =
      err.config?.headers?.Authorization ??
      response?.config?.headers?.Authorization;
    const sentToken =
      typeof authorization === "string" && authorization.startsWith("Bearer ")
        ? authorization.slice(7)
        : "";
    // A delayed401 belongs to the token sent, not a newer login in this browser.
    if (he.status == 401 && sentToken === getLoginToken()) {
      removeLoginToken();
      // Hash router: avoid a hard reload, and don't bounce if already on login.
      const hash = window.location.hash || "";
      if (!hash.includes("/login")) {
        window.location.hash = "#/login";
      }
    }
    if (timeoutErrorCodes.includes(err.code)) {
      he.category = "timeout";
      he.message =
        "Request timed out. Reload policies and config versions to check the outcome before retrying.";
    } else if (response) {
      he.message = apiErrorMessage(
        response.data,
        `Request failed (HTTP ${he.status})`,
      );
      he.category =
        typeof response.data?.category === "string"
          ? response.data.category
          : "api";
    }
    addRequestStats(response?.config, response, he);
    return Promise.reject(he);
  },
);

export default request;
