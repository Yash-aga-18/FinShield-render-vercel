// src/utils/cookies.js

import { durationFromEnv } from "./env.js";

/**
 * Centralized Base Cookie Policy
 *
 * NODE_ENV is evaluated when the function is called rather than
 * when this module is imported. This keeps the cookie policy
 * correct even when the environment changes during testing.
 */
export const getBaseCookieOptions = () => {
  const isProduction = process.env.NODE_ENV === "production";

  return {
    httpOnly: true,
    secure: isProduction,
    sameSite: isProduction ? "strict" : "lax",
    path: "/",
  };
};

/**
 * Cookie names. In production the __Host- prefix is applied, which browsers
 * enforce strictly: the cookie must be Secure, have Path=/, and no Domain
 * attribute — preventing any subdomain from writing (or tossing) these cookies.
 */
export const getCookieNames = () => {
  const isProduction = process.env.NODE_ENV === "production";
  const prefix = isProduction ? "__Host-" : "";

  return {
    access: `${prefix}access_token`,
    refresh: `${prefix}refresh_token`,
  };
};

// Cookie lifetimes follow the token lifetimes so a cookie never outlives
// (or dies before) the JWT it carries. JWT_ACCESS_EXPIRES_IN /
// JWT_REFRESH_EXPIRES_IN use the same "15m" / "7d" duration syntax as
// the jsonwebtoken library itself.
const ACCESS_COOKIE_MAX_AGE_MS =
  durationFromEnv("JWT_ACCESS_EXPIRES_IN", 15 * 60) * 1000;
const REFRESH_COOKIE_MAX_AGE_MS =
  durationFromEnv("JWT_REFRESH_EXPIRES_IN", 7 * 24 * 60 * 60) * 1000;

/**
 * Sets Access and Refresh Tokens into secure HTTP-Only cookies
 */
export const setAuthCookies = (res, accessToken, refreshToken) => {
  const baseOptions = getBaseCookieOptions();
  const names = getCookieNames();

  res.cookie(names.access, accessToken, {
    ...baseOptions,
    maxAge: ACCESS_COOKIE_MAX_AGE_MS,
  });

  res.cookie(names.refresh, refreshToken, {
    ...baseOptions,
    maxAge: REFRESH_COOKIE_MAX_AGE_MS,
  });
};

/**
 * Clears Authentication Cookies completely across paths
 */
export const clearAuthCookies = (res) => {
  const baseOptions = getBaseCookieOptions();
  const names = getCookieNames();

  res.clearCookie(names.access, {
    path: baseOptions.path,
    httpOnly: baseOptions.httpOnly,
    secure: baseOptions.secure,
    sameSite: baseOptions.sameSite,
  });

  res.clearCookie(names.refresh, {
    path: baseOptions.path,
    httpOnly: baseOptions.httpOnly,
    secure: baseOptions.secure,
    sameSite: baseOptions.sameSite,
  });
};
