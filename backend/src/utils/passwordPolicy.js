// src/utils/passwordPolicy.js

/*
 * Password length policy, driven by the environment so ops can tighten it
 * without a deploy — same pattern as namePolicy.js.
 *
 * The minimum is capped at 72 because bcrypt silently truncates input at 72
 * bytes; requiring more than that would make the extra characters decorative.
 */

import { numberFromEnv } from "./env.js";

export const PASSWORD_MIN_LENGTH = numberFromEnv("PASSWORD_MIN_LENGTH", 8, { minimum: 6, maximum: 72 });
export const PASSWORD_MAX_LENGTH = Math.max(
  PASSWORD_MIN_LENGTH,
  numberFromEnv("PASSWORD_MAX_LENGTH", 128, { minimum: 8, maximum: 256 }),
);
