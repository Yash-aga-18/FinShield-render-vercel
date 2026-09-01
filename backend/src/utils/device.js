// src/utils/device.js

/* Client identification from a User-Agent string. Besides real browsers we
   explicitly recognize scripted/API clients (curl, axios, bots, …) — a
   session that shows up in the admin panel as "curl / Unknown OS" or
   "Python client / Unknown OS" is far more actionable than a sea of
   "Unknown Browser / Unknown OS" rows when hunting probe traffic. */

const getBrowser = (userAgent = "") => {
  const ua = userAgent.toLowerCase();

  if (!ua) return "Unknown client";
  if (ua.includes("edg/")) return "Edge";
  if (ua.includes("opr/") || ua.includes("opera")) return "Opera";
  if (ua.includes("chrome/") && !ua.includes("edg/")) return "Chrome";
  if (ua.includes("firefox/")) return "Firefox";
  if (ua.includes("safari/") && !ua.includes("chrome/")) return "Safari";
  if (ua.includes("postmanruntime")) return "Postman";
  if (ua.includes("insomnia")) return "Insomnia";
  if (ua.includes("httpie")) return "HTTPie";
  if (ua.includes("curl/")) return "curl";
  if (ua.includes("wget")) return "Wget";
  if (ua.includes("python-requests") || ua.includes("python-urllib") || ua.includes("aiohttp") || ua.includes("httpx")) return "Python client";
  if (ua.includes("node-fetch") || ua.includes("axios") || ua.includes("undici") || ua.includes("got (")) return "Node client";
  if (ua.includes("go-http-client")) return "Go client";
  if (ua.includes("okhttp")) return "OkHttp";
  if (ua.includes("java/") || ua.includes("apache-httpclient")) return "Java client";
  if (ua.includes("bot") || ua.includes("spider") || ua.includes("crawl") || ua.includes("headless")) return "Bot / crawler";

  return "Unknown Browser";
};

const getOperatingSystem = (userAgent = "") => {
  const ua = userAgent.toLowerCase();

  if (!ua) return "no user-agent";
  if (ua.includes("windows")) return "Windows";
  if (ua.includes("android")) return "Android";
  if (ua.includes("iphone")) return "iOS";
  if (ua.includes("ipad")) return "iPadOS";
  if (ua.includes("mac os") || ua.includes("macintosh")) return "macOS";
  if (ua.includes("linux")) return "Linux";

  return "Unknown OS";
};

const getDeviceType = (userAgent = "") => {
  const ua = userAgent.toLowerCase();

  if (!ua) return "Scripted client";

  if (
    ua.includes("mobile") ||
    ua.includes("android") ||
    ua.includes("iphone")
  ) {
    return "Mobile";
  }

  if (ua.includes("ipad") || ua.includes("tablet")) {
    return "Tablet";
  }

  return "Desktop";
};

export const getDeviceInfo = (userAgent = "") => {
  return {
    browser: getBrowser(userAgent),
    operatingSystem: getOperatingSystem(userAgent),
    type: getDeviceType(userAgent),
  };
};

export const getDeviceLabel = (userAgent = "") => {
  const device = getDeviceInfo(userAgent);
  return `${device.browser} / ${device.operatingSystem}`;
};
